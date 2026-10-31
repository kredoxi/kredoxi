package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kredoxi/kredoxi/examples"
	"github.com/kredoxi/kredoxi/internal/devruntime"
	"github.com/kredoxi/kredoxi/internal/resolver"
	"github.com/kredoxi/kredoxi/internal/synthetic"
)

func moduleRoot() (string, error) {
	directory, err := os.Getwd()
	if err != nil {
		return "", errors.New("repository root unavailable")
	}
	for {
		data, readErr := os.ReadFile(filepath.Join(directory, "go.mod"))
		if readErr == nil && strings.Contains(string(data), "module github.com/kredoxi/kredoxi") {
			return directory, nil
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			return "", errors.New("repository root unavailable")
		}
		directory = parent
	}
}

func randomCredential() (string, error) {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return "", resolver.InternalFailure
	}
	return hex.EncodeToString(value), nil
}

func appendTLSSecrets(secrets [][]byte, materials ...synthetic.TLSMaterial) [][]byte {
	for _, material := range materials {
		secrets = append(secrets, material.PrivateKey)
		encoded := make([]byte, base64.StdEncoding.EncodedLen(len(material.PrivateKey)))
		base64.StdEncoding.Encode(encoded, material.PrivateKey)
		secrets = append(secrets, encoded)
	}
	return secrets
}

func startBroker(binary string, bootstrap devruntime.BrokerBootstrap, outputs *outputSet) (*childProcess, string, error) {
	return startExecutable(binary, "broker", nil, bootstrap, true, outputs.process("broker"), startupTimeout)
}

func startService(binary string, bootstrap devruntime.ServiceBootstrap, outputs *outputSet) (*childProcess, string, error) {
	return startExecutable(binary, "service", nil, bootstrap, true, outputs.process("service"), startupTimeout)
}

func startConsumer(binary, root string, material synthetic.TLSMaterial, brokerAddress, serviceAddress, expectedError string, outputs *outputSet) (*childProcess, error) {
	bootstrap := devruntime.ConsumerBootstrap{
		TLS: material, BrokerAddress: brokerAddress, ServiceAddress: serviceAddress,
	}
	args := []string{"--config", filepath.Join(root, "examples", "consumer.json")}
	if expectedError != "" {
		args = append(args, "--expect-error", expectedError)
	}
	child, _, err := startExecutable(
		binary, "consumer", args, bootstrap, true, outputs.process("consumer"), startupTimeout,
	)
	return child, err
}

func runConsumer(binary, root string, material synthetic.TLSMaterial, brokerAddress, serviceAddress, expectedError string, outputs *outputSet) error {
	child, err := startConsumer(binary, root, material, brokerAddress, serviceAddress, expectedError, outputs)
	if err != nil {
		return err
	}
	ack, err := child.control("resolve", controlTimeout)
	if err != nil || !ack.Applied {
		_ = child.terminate(shutdownTimeout)
		return errors.New("consumer resolution gate failed")
	}
	if err := child.closeInput(); err != nil {
		_ = child.terminate(shutdownTimeout)
		return err
	}
	return child.wait(15 * time.Second)
}

func makeBrokerBootstrap(serverMaterial synthetic.TLSMaterial, credential string) devruntime.BrokerBootstrap {
	digest := sha256.Sum256([]byte(examples.TrustedPolicy))
	return devruntime.BrokerBootstrap{
		TLS: serverMaterial, Policy: examples.Policy,
		PolicyDigest: hex.EncodeToString(digest[:]),
		Reference:    examples.Reference, Credential: credential,
	}
}

func run() error {
	return runWithWriters(os.Stdout, os.Stderr, nil)
}

func runWithWriters(stdout, stderr io.Writer, observe func(*outputSet)) (err error) {
	outputs := newOutputSet()
	var binaries map[string]string
	var broker, service *childProcess
	var secrets [][]byte
	defer func() {
		if broker != nil {
			err = errors.Join(err, broker.stopBroker())
		}
		if service != nil {
			err = errors.Join(err, service.stopControlled())
		}
		if !allProcessesStopped(outputs) {
			err = errors.Join(err, errors.New("temporary executable cleanup skipped because child exit was not confirmed"))
		} else {
			err = errors.Join(err, assertBuildDirectoryRedacted(outputs, secrets...))
			err = errors.Join(err, removeBuildDirectory(outputs))
		}
		err = errors.Join(err, outputs.assertRedacted(secrets...))
		if err == nil {
			err = outputs.writeSupervisor(stdout, stderr)
		}
		if observe != nil {
			observe(outputs)
		}
	}()

	root, err := moduleRoot()
	if err != nil {
		return err
	}
	binaries, err = buildExecutables(root, outputs)
	if err != nil {
		return err
	}
	credential, err := randomCredential()
	if err != nil {
		return err
	}
	pki, err := synthetic.NewPKI()
	if err != nil {
		return resolver.InternalFailure
	}
	serverMaterial, err := pki.ServerMaterial()
	if err != nil {
		return resolver.InternalFailure
	}
	authorizedMaterial, err := pki.ClientMaterial(examples.Principal)
	if err != nil {
		return resolver.InternalFailure
	}
	unauthorizedMaterial, err := pki.ClientMaterial("urn:kredoxi:principal:unauthorized")
	if err != nil {
		return resolver.InternalFailure
	}
	brokerBootstrap := makeBrokerBootstrap(serverMaterial, credential)
	serviceBootstrap := devruntime.ServiceBootstrap{Credential: credential}
	secrets = append(secrets, []byte(credential))
	secrets = appendTLSSecrets(secrets, serverMaterial, authorizedMaterial, unauthorizedMaterial)

	service, serviceAddress, err := startService(binaries["service"], serviceBootstrap, outputs)
	if err != nil {
		return err
	}
	broker, brokerAddress, err := startBroker(binaries["broker"], brokerBootstrap, outputs)
	if err != nil {
		return err
	}
	if err := runConsumer(binaries["consumer"], root, authorizedMaterial, brokerAddress, serviceAddress, "", outputs); err != nil {
		return err
	}
	fmt.Fprintln(outputs.capture("supervisor.stderr"), "demo: authorized consumer used the synthetic service")
	if err := runConsumer(binaries["consumer"], root, unauthorizedMaterial, brokerAddress, serviceAddress, string(resolver.PolicyDenied), outputs); err != nil {
		return err
	}
	fmt.Fprintln(outputs.capture("supervisor.stderr"), "demo: unauthorized consumer received policy_denied")
	if err := broker.requireApplied("provider-unavailable", controlTimeout); err != nil {
		return err
	}
	if err := runConsumer(binaries["consumer"], root, authorizedMaterial, brokerAddress, serviceAddress, string(resolver.ProviderUnavailable), outputs); err != nil {
		return err
	}
	fmt.Fprintln(outputs.capture("supervisor.stderr"), "demo: provider outage returned provider_unavailable")
	if err := broker.requireApplied("provider-available", controlTimeout); err != nil {
		return err
	}
	if err := runConsumer(binaries["consumer"], root, authorizedMaterial, brokerAddress, serviceAddress, "", outputs); err != nil {
		return err
	}
	if err := broker.stopBroker(); err != nil {
		return err
	}
	broker = nil
	if err := runConsumer(binaries["consumer"], root, authorizedMaterial, brokerAddress, serviceAddress, string(resolver.BrokerUnavailable), outputs); err != nil {
		return err
	}
	fmt.Fprintln(outputs.capture("supervisor.stderr"), "demo: stopped broker returned broker_unavailable")
	if err := service.stopControlled(); err != nil {
		return err
	}
	service = nil

	rotatedCredential, err := randomCredential()
	if err != nil {
		return err
	}
	rotatedPKI, err := synthetic.NewPKI()
	if err != nil {
		return resolver.InternalFailure
	}
	rotatedServerMaterial, err := rotatedPKI.ServerMaterial()
	if err != nil {
		return resolver.InternalFailure
	}
	rotatedClientMaterial, err := rotatedPKI.ClientMaterial(examples.Principal)
	if err != nil {
		return resolver.InternalFailure
	}
	rotatedBrokerBootstrap := makeBrokerBootstrap(rotatedServerMaterial, rotatedCredential)
	rotatedServiceBootstrap := devruntime.ServiceBootstrap{Credential: rotatedCredential}
	secrets = append(secrets, []byte(rotatedCredential))
	secrets = appendTLSSecrets(secrets, rotatedServerMaterial, rotatedClientMaterial)
	service, serviceAddress, err = startService(binaries["service"], rotatedServiceBootstrap, outputs)
	if err != nil {
		return err
	}
	broker, brokerAddress, err = startBroker(binaries["broker"], rotatedBrokerBootstrap, outputs)
	if err != nil {
		return err
	}
	if err := runConsumer(binaries["consumer"], root, authorizedMaterial, brokerAddress, serviceAddress, string(resolver.BrokerUnavailable), outputs); err != nil {
		return err
	}
	if err := runConsumer(binaries["consumer"], root, rotatedClientMaterial, brokerAddress, serviceAddress, "", outputs); err != nil {
		return err
	}
	fmt.Fprintln(outputs.capture("supervisor.stderr"), "demo: broker restart used fresh synthetic identity and provider state")
	if err := broker.stopBroker(); err != nil {
		return err
	}
	broker = nil
	if err := service.stopControlled(); err != nil {
		return err
	}
	service = nil
	fmt.Fprintln(outputs.capture("supervisor.stderr"), "demo: graceful shutdown verified; OS-account identity was not tested")
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "demo failed:", err)
		os.Exit(1)
	}
}
