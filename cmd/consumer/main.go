package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/kredoxi/kredoxi/internal/devruntime"
	"github.com/kredoxi/kredoxi/internal/resolver"
	"github.com/kredoxi/kredoxi/internal/synthetic"
)

func run() error {
	configPath := flag.String("config", "", "reference-only consumer JSON configuration")
	expectedFailure := flag.String("expect-error", "", "development demo expected error category")
	flag.Parse()
	if *configPath == "" {
		return resolver.InvalidRequest
	}
	reader := bufio.NewReaderSize(os.Stdin, 32*1024+1)
	var bootstrap devruntime.ConsumerBootstrap
	if err := devruntime.Decode(reader, &bootstrap); err != nil {
		return resolver.InvalidRequest
	}
	config, err := os.Open(*configPath)
	if err != nil {
		return resolver.InvalidRequest
	}
	data, readErr := io.ReadAll(io.LimitReader(config, 1025))
	closeErr := config.Close()
	if readErr != nil || closeErr != nil || len(data) > 1024 {
		return resolver.InvalidRequest
	}
	tlsConfig, err := synthetic.ClientConfigFromMaterial(bootstrap.TLS)
	if err != nil {
		return resolver.InvalidRequest
	}
	client, err := resolver.NewClient(bootstrap.BrokerAddress, tlsConfig)
	if err != nil {
		return resolver.InvalidRequest
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	err = resolver.Consume(ctx, client, data, func(credential string) error {
		return synthetic.AuthenticateService(ctx, bootstrap.ServiceAddress, credential)
	})
	if *expectedFailure != "" {
		if err != nil && resolver.Category(*expectedFailure) == resolver.Category(err.Error()) {
			fmt.Fprintln(os.Stderr, "consumer: expected", *expectedFailure)
			return nil
		}
		return errors.New("consumer: unexpected_result")
	}
	if err != nil {
		return errors.New("consumer: request_failed")
	}
	fmt.Fprintln(os.Stderr, "consumer: synthetic service challenge authenticated")
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "consumer: startup_or_runtime_failure")
		os.Exit(1)
	}
}
