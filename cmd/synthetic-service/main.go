package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"

	"github.com/kredoxi/kredoxi/internal/devruntime"
	"github.com/kredoxi/kredoxi/internal/synthetic"
)

func run() error {
	reader := bufio.NewReaderSize(os.Stdin, 32*1024+1)
	var bootstrap devruntime.ServiceBootstrap
	if err := devruntime.Decode(reader, &bootstrap); err != nil {
		return errors.New("invalid development bootstrap")
	}
	service, err := synthetic.StartService(bootstrap.Credential)
	if err != nil {
		return errors.New("synthetic service startup failed")
	}
	if _, err := fmt.Fprintf(os.Stderr, "KREDOXI_READY service %s\n", service.Address()); err != nil {
		if closeErr := service.Close(); closeErr != nil {
			return errors.New("synthetic service shutdown failed")
		}
		return errors.New("synthetic service startup failed")
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
	running := true
	for running {
		select {
		case <-ctx.Done():
			running = false
		case input := <-control:
			if input.err != nil {
				if !errors.Is(input.err, io.EOF) {
					if closeErr := service.Close(); closeErr != nil {
						return errors.New("synthetic service shutdown failed")
					}
					return errors.New("invalid development control")
				}
				running = false
				continue
			}
			applied := false
			if input.command.Operation == "stop" {
				if closeErr := service.Close(); closeErr != nil {
					return errors.New("synthetic service shutdown failed")
				}
				applied = true
				running = false
			}
			if err := devruntime.WriteControlAck(os.Stderr, devruntime.ControlAck{
				ID: input.command.ID, Operation: input.command.Operation, Applied: applied,
			}); err != nil {
				return errors.New("development control acknowledgement failed")
			}
		}
	}
	if err := service.Close(); err != nil {
		return errors.New("synthetic service shutdown failed")
	}
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "synthetic-service: startup_or_runtime_failure")
		os.Exit(1)
	}
}
