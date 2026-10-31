package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"time"

	"github.com/kredoxi/kredoxi/internal/devruntime"
	"github.com/kredoxi/kredoxi/internal/resolver"
	"github.com/kredoxi/kredoxi/internal/synthetic"
)

type controlledProvider struct {
	base    resolver.Provider
	mu      sync.Mutex
	held    chan struct{}
	active  int
	changed chan struct{}
}

func newControlledProvider(base resolver.Provider) *controlledProvider {
	return &controlledProvider{base: base, changed: make(chan struct{})}
}

func (p *controlledProvider) notifyLocked() {
	close(p.changed)
	p.changed = make(chan struct{})
}

func (p *controlledProvider) SetHeld(held bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if held {
		if p.held == nil {
			p.held = make(chan struct{})
			p.notifyLocked()
		}
		return
	}
	if p.held != nil {
		close(p.held)
		p.held = nil
		p.notifyLocked()
	}
}

func (p *controlledProvider) WaitForActive(ctx context.Context) error {
	for {
		p.mu.Lock()
		if p.active > 0 {
			p.mu.Unlock()
			return nil
		}
		changed := p.changed
		p.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (p *controlledProvider) IsIdle() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.active == 0
}

func (p *controlledProvider) Resolve(ctx context.Context, reference resolver.Reference) (string, error) {
	p.mu.Lock()
	p.active++
	held := p.held
	p.notifyLocked()
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		p.active--
		p.notifyLocked()
		p.mu.Unlock()
	}()
	if held != nil {
		select {
		case <-held:
		case <-ctx.Done():
			return "", resolver.Canceled
		}
	}
	return p.base.Resolve(ctx, reference)
}

func run() error {
	reader := bufio.NewReaderSize(os.Stdin, 32*1024+1)
	var bootstrap devruntime.BrokerBootstrap
	if err := devruntime.Decode(reader, &bootstrap); err != nil {
		return errors.New("invalid development bootstrap")
	}
	digestBytes, err := hex.DecodeString(bootstrap.PolicyDigest)
	if err != nil || len(digestBytes) != 32 {
		return errors.New("invalid development bootstrap")
	}
	var digest [32]byte
	copy(digest[:], digestBytes)
	policy, err := resolver.NewPolicy(bootstrap.Policy, digest)
	if err != nil {
		return resolver.InvalidPolicy
	}
	if _, err := resolver.ParseReference(bootstrap.Reference); err != nil {
		return resolver.InvalidReference
	}
	baseProvider, err := resolver.NewSyntheticProviderWithValues(map[string]string{
		bootstrap.Reference: bootstrap.Credential,
	})
	if err != nil {
		return err
	}
	provider := newControlledProvider(baseProvider)
	serverTLS, err := synthetic.ServerConfigFromMaterial(bootstrap.TLS)
	if err != nil {
		return resolver.InvalidRequest
	}
	telemetry, err := resolver.NewTelemetry(os.Stdout)
	if err != nil {
		return err
	}
	broker, err := resolver.Start(serverTLS, policy, provider, telemetry)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(os.Stderr, "KREDOXI_READY broker %s\n", broker.Address()); err != nil {
		if closeErr := broker.Close(); closeErr != nil {
			return errors.New("broker shutdown failed")
		}
		return errors.New("broker startup failed")
	}
	ctx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stopSignals()
	type controlInput struct {
		command devruntime.ControlCommand
		err     error
	}
	control := make(chan controlInput, 1)
	go func() {
		for {
			command, err := devruntime.ReadControl(reader)
			control <- controlInput{command: command, err: err}
			if err != nil || command.Operation == "stop" {
				return
			}
		}
	}()
	running, brokerClosed := true, false
	var controlErr error
	for running {
		select {
		case <-ctx.Done():
			running = false
		case input := <-control:
			if input.err != nil {
				controlErr = errors.New("development control failed")
				running = false
				continue
			}
			command := input.command
			applied := true
			switch command.Operation {
			case "provider-unavailable":
				baseProvider.SetAvailable(false)
			case "provider-available":
				baseProvider.SetAvailable(true)
			case "provider-hold":
				provider.SetHeld(true)
			case "provider-release":
				provider.SetHeld(false)
			case "await-provider":
				waitCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				applied = provider.WaitForActive(waitCtx) == nil
				cancel()
			case "provider-idle":
				applied = provider.IsIdle()
			case "stop":
				if err := broker.Close(); err != nil {
					controlErr = errors.New("broker shutdown failed")
					applied = false
				} else {
					brokerClosed = true
				}
			default:
				applied = false
			}
			if err := devruntime.WriteControlAck(os.Stderr, devruntime.ControlAck{
				ID: command.ID, Operation: command.Operation, Applied: applied,
			}); err != nil {
				controlErr = errors.New("development control acknowledgement failed")
				running = false
				continue
			}
			if command.Operation == "stop" && applied {
				running = false
			}
		}
	}
	if !brokerClosed {
		if err := broker.Close(); err != nil && controlErr == nil {
			return err
		}
	}
	return controlErr
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "broker: startup_or_runtime_failure")
		os.Exit(1)
	}
}
