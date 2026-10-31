package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"

	"github.com/kredoxi/kredoxi/examples"
	"github.com/kredoxi/kredoxi/internal/resolver"
	"github.com/kredoxi/kredoxi/internal/synthetic"
)

func run() (err error) {
	pki, err := synthetic.NewPKI()
	if err != nil {
		return resolver.InternalFailure
	}
	serverTLS, err := pki.ServerConfig()
	if err != nil {
		return resolver.InternalFailure
	}
	clientTLS, err := pki.ClientConfig(examples.Principal)
	if err != nil {
		return resolver.InternalFailure
	}
	deniedTLS, err := pki.ClientConfig("urn:kredoxi:principal:unauthorized")
	if err != nil {
		return resolver.InternalFailure
	}
	policy, err := resolver.NewPolicy(examples.Policy, sha256.Sum256([]byte(examples.TrustedPolicy)))
	if err != nil {
		return err
	}
	provider, err := resolver.NewSyntheticProvider([]string{examples.Reference})
	if err != nil {
		return err
	}
	reference, err := resolver.ParseReference(examples.Reference)
	if err != nil {
		return err
	}
	serviceCredential, err := provider.Resolve(context.Background(), reference)
	if err != nil {
		return err
	}
	telemetry, err := resolver.NewTelemetry(os.Stdout)
	if err != nil {
		return err
	}
	broker, err := resolver.Start(serverTLS, policy, provider, telemetry)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := broker.Close(); closeErr != nil && err == nil {
			err = closeErr
		}
	}()
	client, err := resolver.NewClient(broker.Address(), clientTLS)
	if err != nil {
		return err
	}
	defer client.Close()
	ctx := context.Background()
	err = resolver.Consume(ctx, client, examples.Consumer, func(credential string) error {
		challenge := make([]byte, 32)
		if _, err := rand.Read(challenge); err != nil {
			return resolver.InternalFailure
		}
		proof := hmac.New(sha256.New, []byte(credential))
		if _, err := proof.Write(challenge); err != nil {
			return resolver.InternalFailure
		}
		expected := hmac.New(sha256.New, []byte(serviceCredential))
		if _, err := expected.Write(challenge); err != nil {
			return resolver.InternalFailure
		}
		if !hmac.Equal(proof.Sum(nil), expected.Sum(nil)) {
			return errors.New("proof_denied")
		}
		return nil
	})
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "consumer: synthetic service challenge authenticated; config contains only a reference")
	denied, err := resolver.NewClient(broker.Address(), deniedTLS)
	if err != nil {
		return err
	}
	defer denied.Close()
	if _, err := denied.Resolve(ctx, examples.Reference); !errors.Is(err, resolver.PolicyDenied) {
		return errors.New("unauthorized_demo_failed")
	}
	fmt.Fprintln(os.Stderr, "unauthorized caller: policy_denied")
	provider.SetAvailable(false)
	if _, err := client.Resolve(ctx, examples.Reference); !errors.Is(err, resolver.ProviderUnavailable) {
		return errors.New("provider_failure_demo_failed")
	}
	fmt.Fprintln(os.Stderr, "unavailable provider: provider_unavailable")
	if err := broker.Close(); err != nil {
		return err
	}
	if _, err := client.Resolve(ctx, examples.Reference); !errors.Is(err, resolver.BrokerUnavailable) {
		return errors.New("broker_failure_demo_failed")
	}
	fmt.Fprintln(os.Stderr, "stopped broker: broker_unavailable")
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "demo failed:", err)
		os.Exit(1)
	}
}
