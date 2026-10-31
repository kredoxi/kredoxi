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
	control := make(chan error, 1)
	go func() {
		command, err := devruntime.ReadControl(reader)
		if err == nil && command != "stop" {
			err = errors.New("invalid development control")
		}
		control <- err
	}()
	select {
	case <-ctx.Done():
	case err := <-control:
		if err != nil && !errors.Is(err, io.EOF) {
			if closeErr := service.Close(); closeErr != nil {
				return errors.New("synthetic service shutdown failed")
			}
			return errors.New("invalid development control")
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
