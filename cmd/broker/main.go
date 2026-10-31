package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"

	"github.com/kredoxi/kredoxi/internal/devruntime"
	"github.com/kredoxi/kredoxi/internal/resolver"
	"github.com/kredoxi/kredoxi/internal/synthetic"
)

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
	provider, err := resolver.NewSyntheticProviderWithValues(map[string]string{
		bootstrap.Reference: bootstrap.Credential,
	})
	if err != nil {
		return err
	}
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
	control := make(chan struct {
		command string
		err     error
	}, 1)
	go func() {
		for {
			command, err := devruntime.ReadControl(reader)
			control <- struct {
				command string
				err     error
			}{command: command, err: err}
			if err != nil || command == "stop" {
				return
			}
		}
	}()
	running := true
	var controlErr error
	for running {
		select {
		case <-ctx.Done():
			running = false
		case input := <-control:
			if input.err != nil {
				if errors.Is(input.err, io.EOF) {
					running = false
					continue
				}
				controlErr = errors.New("development control failed")
				running = false
				continue
			}
			switch input.command {
			case "provider-unavailable":
				provider.SetAvailable(false)
			case "provider-available":
				provider.SetAvailable(true)
			case "stop":
				running = false
			default:
				controlErr = errors.New("invalid development control")
				running = false
			}
		}
	}
	if err := broker.Close(); err != nil {
		return err
	}
	return controlErr
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "broker: startup_or_runtime_failure")
		os.Exit(1)
	}
}
