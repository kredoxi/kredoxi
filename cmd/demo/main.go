package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kredoxi/kredoxi/examples"
	"github.com/kredoxi/kredoxi/internal/devruntime"
	"github.com/kredoxi/kredoxi/internal/resolver"
	"github.com/kredoxi/kredoxi/internal/synthetic"
)

type childProcess struct {
	name   string
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	done   chan error
	failed bool
	result error
}

type auditCapture struct {
	mu   sync.Mutex
	data bytes.Buffer
}

func (c *auditCapture) Write(data []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, err := c.data.Write(data); err != nil {
		return 0, err
	}
	return os.Stdout.Write(data)
}

func (c *auditCapture) contains(value string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return bytes.Contains(c.data.Bytes(), []byte(value))
}

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

func startProcess(root, name, packagePath string, args []string, bootstrap any, stdout io.Writer, waitForReady bool) (*childProcess, string, error) {
	data, err := devruntime.Encode(bootstrap)
	if err != nil {
		return nil, "", errors.New("development bootstrap failed")
	}
	commandArgs := append([]string{"run", packagePath}, args...)
	command := exec.Command("go", commandArgs...)
	command.Dir = root
	command.Stdout = stdout
	stderr, err := command.StderrPipe()
	if err != nil {
		return nil, "", errors.New("process startup failed")
	}
	input, err := command.StdinPipe()
	if err != nil {
		return nil, "", errors.New("process startup failed")
	}
	if err := command.Start(); err != nil {
		return nil, "", errors.New("process startup failed")
	}
	child := &childProcess{name: name, cmd: command, stdin: input, done: make(chan error, 1)}
	go func() { child.done <- command.Wait() }()
	ready := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(stderr)
		prefix := "KREDOXI_READY " + name + " "
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, prefix) {
				ready <- strings.TrimSpace(strings.TrimPrefix(line, prefix))
				continue
			}
			fmt.Fprintln(os.Stderr, line)
		}
		if err := scanner.Err(); err != nil {
			fmt.Fprintln(os.Stderr, "child diagnostic stream failed")
		}
	}()
	if _, err := input.Write(data); err != nil {
		child.terminate()
		return nil, "", errors.New("process bootstrap failed")
	}
	if !waitForReady {
		if err := input.Close(); err != nil {
			child.terminate()
			return nil, "", errors.New("process bootstrap failed")
		}
		return child, "", nil
	}
	select {
	case address := <-ready:
		if err := validateAddress(address); err != nil {
			child.terminate()
			return nil, "", err
		}
		return child, address, nil
	case processErr := <-child.done:
		child.result = processErr
		child.failed = true
		return nil, "", errors.New("process exited before readiness")
	case <-time.After(30 * time.Second):
		child.terminate()
		return nil, "", errors.New("process startup timed out")
	}
}

func validateAddress(address string) error {
	host, port, err := net.SplitHostPort(address)
	number, portErr := strconv.Atoi(port)
	if err != nil || portErr != nil || host != "127.0.0.1" || number < 1 || number > 65535 {
		return errors.New("child returned an invalid loopback address")
	}
	return nil
}

func (p *childProcess) send(command string) error {
	if p == nil || p.failed {
		return errors.New("process is not running")
	}
	if _, err := fmt.Fprintln(p.stdin, command); err != nil {
		return errors.New("process control failed")
	}
	return nil
}

func (p *childProcess) wait(timeout time.Duration) error {
	if p.failed {
		return p.result
	}
	select {
	case p.result = <-p.done:
		p.failed = true
		if p.result != nil {
			return errors.New("child process failed")
		}
		return nil
	case <-time.After(timeout):
		p.terminate()
		return errors.New("child process shutdown timed out")
	}
}

func (p *childProcess) stop() error {
	if p == nil || p.failed {
		return nil
	}
	_ = p.send("stop")
	_ = p.stdin.Close()
	return p.wait(10 * time.Second)
}

func (p *childProcess) terminate() {
	if p == nil {
		return
	}
	_ = p.stdin.Close()
	if p.cmd.Process != nil {
		_ = p.cmd.Process.Kill()
	}
	if !p.failed {
		p.result = <-p.done
		p.failed = true
	}
}

func startBroker(root string, bootstrap devruntime.BrokerBootstrap, audit io.Writer) (*childProcess, string, error) {
	return startProcess(root, "broker", "./cmd/broker", nil, bootstrap, audit, true)
}

func runConsumer(root string, material synthetic.TLSMaterial, brokerAddress, serviceAddress, expectedError string) error {
	bootstrap := devruntime.ConsumerBootstrap{
		TLS: material, BrokerAddress: brokerAddress, ServiceAddress: serviceAddress,
	}
	args := []string{"--config", filepath.Join(root, "examples", "consumer.json")}
	if expectedError != "" {
		args = append(args, "--expect-error", expectedError)
	}
	child, _, err := startProcess(root, "consumer", "./cmd/consumer", args, bootstrap, io.Discard, false)
	if err != nil {
		return err
	}
	return child.wait(15 * time.Second)
}

func run() (err error) {
	root, err := moduleRoot()
	if err != nil {
		return err
	}
	randomCredential := make([]byte, 32)
	if _, err := rand.Read(randomCredential); err != nil {
		return resolver.InternalFailure
	}
	credential := hex.EncodeToString(randomCredential)
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
	policyDigest := sha256.Sum256([]byte(examples.TrustedPolicy))
	brokerBootstrap := devruntime.BrokerBootstrap{
		TLS: serverMaterial, Policy: examples.Policy,
		PolicyDigest: hex.EncodeToString(policyDigest[:]),
		Reference:    examples.Reference, Credential: credential,
	}
	auditOutput := &auditCapture{}
	service, serviceAddress, err := startProcess(root, "service", "./cmd/synthetic-service", nil,
		devruntime.ServiceBootstrap{Credential: credential}, io.Discard, true)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := service.stop(); err == nil && closeErr != nil {
			err = closeErr
		}
	}()
	broker, brokerAddress, err := startBroker(root, brokerBootstrap, auditOutput)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := broker.stop(); err == nil && closeErr != nil {
			err = closeErr
		}
	}()
	if err := runConsumer(root, authorizedMaterial, brokerAddress, serviceAddress, ""); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "demo: authorized consumer used the synthetic service from a separate process")
	if err := runConsumer(root, unauthorizedMaterial, brokerAddress, serviceAddress, string(resolver.PolicyDenied)); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "demo: unauthorized process received policy_denied")
	if err := broker.send("provider-unavailable"); err != nil {
		return err
	}
	if err := runConsumer(root, authorizedMaterial, brokerAddress, serviceAddress, string(resolver.ProviderUnavailable)); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "demo: provider outage returned provider_unavailable")
	if err := broker.stop(); err != nil {
		return err
	}
	broker = nil
	if err := runConsumer(root, authorizedMaterial, brokerAddress, serviceAddress, string(resolver.BrokerUnavailable)); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "demo: stopped broker returned broker_unavailable")
	broker, brokerAddress, err = startBroker(root, brokerBootstrap, auditOutput)
	if err != nil {
		return err
	}
	if err := runConsumer(root, authorizedMaterial, brokerAddress, serviceAddress, ""); err != nil {
		return err
	}
	if err := broker.stop(); err != nil {
		return err
	}
	broker = nil
	if err := service.stop(); err != nil {
		return err
	}
	service = nil
	for _, sensitive := range []string{credential, examples.Reference, examples.Principal} {
		if auditOutput.contains(sensitive) {
			return errors.New("demo telemetry contains sensitive data")
		}
	}
	fmt.Fprintln(os.Stderr, "demo: broker restart and graceful shutdown succeeded; OS-account identity was not tested")
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "demo failed:", err)
		os.Exit(1)
	}
}
