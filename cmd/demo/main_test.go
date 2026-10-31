package main

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/kredoxi/kredoxi/examples"
	"github.com/kredoxi/kredoxi/internal/devruntime"
	"github.com/kredoxi/kredoxi/internal/synthetic"
)

func TestIndependentProcessDemo(t *testing.T) {
	var outputs *outputSet
	var stdout, stderr bytes.Buffer
	if err := runWithWriters(&stdout, &stderr, func(result *outputSet) { outputs = result }); err != nil {
		t.Fatal(err)
	}
	if outputs == nil {
		t.Fatal("demo did not expose captured diagnostics to the test")
	}
	if !allProcessesStopped(outputs) {
		t.Fatal("demo returned before every owned process exited")
	}
	for _, stream := range []string{
		"broker.stdout", "broker.stderr", "consumer.stdout", "consumer.stderr",
		"service.stdout", "service.stderr", "supervisor.stdout", "supervisor.stderr",
		"build.broker.stdout", "build.broker.stderr",
		"build.consumer.stdout", "build.consumer.stderr",
		"build.service.stdout", "build.service.stderr",
	} {
		if outputs.capture(stream) == nil {
			t.Fatalf("missing captured stream %s", stream)
		}
	}
	outputs.mu.Lock()
	buildDirectory := outputs.tempDirectory
	outputs.mu.Unlock()
	if buildDirectory == "" {
		t.Fatal("demo did not use a temporary executable directory")
	}
	if _, err := os.Stat(buildDirectory); !os.IsNotExist(err) {
		t.Fatal("temporary executable directory remained after demo")
	}
	if bytes.Contains(stderr.Bytes(), []byte("PRIVATE KEY")) ||
		bytes.Contains(stdout.Bytes(), []byte("PRIVATE KEY")) {
		t.Fatal("demo output contains private-key material")
	}
}

func TestProcessSupervisorHelper(t *testing.T) {
	mode := os.Getenv("KREDOXI_PROCESS_HELPER")
	if mode == "" {
		return
	}
	if mode == "no-bootstrap-read" {
		<-time.After(time.Hour)
		return
	}
	var bootstrap struct{}
	reader := bufio.NewReader(os.Stdin)
	if err := devruntime.Decode(reader, &bootstrap); err != nil {
		os.Exit(20)
	}
	switch mode {
	case "crash":
		os.Exit(21)
	case "hang":
		listener, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			os.Exit(22)
		}
		fmt.Fprintln(os.Stdout, listener.Addr().String())
		select {}
	case "listen":
		listener, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			os.Exit(22)
		}
		fmt.Fprintln(os.Stdout, listener.Addr().String())
		fmt.Fprintln(os.Stderr, "KREDOXI_READY testchild")
		select {}
	case "supervisor":
		fmt.Fprintln(os.Stderr, "KREDOXI_READY supervisor")
		outputs := newOutputSet()
		childCommand := exec.Command(os.Args[0], "-test.run=^TestProcessSupervisorHelper$")
		childCommand.Env = append(minimalProcessEnvironment(), "KREDOXI_PROCESS_HELPER=listen")
		_, _, err := startCommand(
			childCommand, "testchild", struct{}{}, true, outputs.process("testchild"), time.Second,
		)
		if err != nil {
			fmt.Fprintln(os.Stdout, "KREDOXI_SUPERVISOR_CHILD_START_FAILED")
			os.Exit(27)
		}
		data, _ := outputs.capture("testchild.stdout").snapshot()
		fmt.Fprintf(os.Stdout, "KREDOXI_SUPERVISOR_READY %s\n", strings.TrimSpace(string(data)))
		for {
			time.Sleep(time.Hour)
		}
	case "leak":
		secret := os.Getenv("KREDOXI_PROCESS_SECRET")
		fmt.Fprintln(os.Stdout, secret)
		fmt.Fprintln(os.Stderr, secret)
	case "malformed-ack":
	case "exit-on-control", "no-ack", "stale-ack", "wrong-operation-ack", "duplicate-ack", "ready", "reject":
	default:
		os.Exit(23)
	}
	if mode != "hang" && mode != "listen" {
		fmt.Fprintln(os.Stderr, "KREDOXI_READY testchild")
	}
	for {
		command, err := devruntime.ReadControl(reader)
		if err != nil {
			os.Exit(24)
		}
		if mode == "exit-on-control" {
			os.Exit(26)
		}
		if mode == "no-ack" {
			continue
		}
		if mode == "malformed-ack" {
			fmt.Fprintln(os.Stderr, "KREDOXI_ACK {")
			select {}
		}
		ack := devruntime.ControlAck{ID: command.ID, Operation: command.Operation, Applied: mode != "reject" || command.Operation == "stop"}
		if mode == "stale-ack" {
			ack.ID++
			_ = devruntime.WriteControlAck(os.Stderr, ack)
			ack.ID--
		}
		if mode == "wrong-operation-ack" {
			ack.Operation = "unexpected-operation"
		}
		if err := devruntime.WriteControlAck(os.Stderr, ack); err != nil {
			os.Exit(25)
		}
		if mode == "duplicate-ack" {
			_ = devruntime.WriteControlAck(os.Stderr, ack)
		}
		if command.Operation == "stop" {
			return
		}
	}
}

func startHelper(t *testing.T, mode, secret string, timeout time.Duration) (*childProcess, *outputSet, string, error) {
	t.Helper()
	outputs := newOutputSet()
	command := exec.Command(os.Args[0], "-test.run=^TestProcessSupervisorHelper$")
	command.Env = append(minimalProcessEnvironment(), "KREDOXI_PROCESS_HELPER="+mode)
	if secret != "" {
		command.Env = append(command.Env, "KREDOXI_PROCESS_SECRET="+secret)
	}
	child, address, err := startCommand(
		command, "testchild", struct{}{}, true, outputs.process("testchild"), timeout,
	)
	return child, outputs, address, err
}

func TestOwnedProcessLifecycle(t *testing.T) {
	t.Run("normal shutdown and acknowledged control", func(t *testing.T) {
		child, _, _, err := startHelper(t, "ready", "", time.Second)
		if err != nil {
			t.Fatal("helper failed to become ready")
		}
		ack, err := child.control("provider-hold", time.Second)
		if err != nil || !ack.Applied {
			t.Fatal("applied control was not acknowledged")
		}
		if err := child.stopControlled(); err != nil {
			t.Fatal("controlled shutdown failed")
		}
		if !isClosed(child.finished) {
			t.Fatal("process handle was not reaped")
		}
	})

	t.Run("crash before readiness", func(t *testing.T) {
		child, _, _, err := startHelper(t, "crash", "", time.Second)
		if err == nil || child == nil || !isClosed(child.finished) {
			t.Fatal("startup crash was not detected and reaped")
		}
	})

	t.Run("startup timeout and listener cleanup", func(t *testing.T) {
		child, outputs, _, err := startHelper(t, "hang", "", 150*time.Millisecond)
		if err == nil || child == nil || !isClosed(child.finished) {
			t.Fatal("startup timeout did not terminate and reap the child")
		}
		data, _ := outputs.capture("testchild.stdout").snapshot()
		address := strings.TrimSpace(string(data))
		connection, dialErr := net.DialTimeout("tcp4", address, 150*time.Millisecond)
		if dialErr == nil {
			_ = connection.Close()
			t.Fatal("listener survived forced child termination")
		}
	})

	t.Run("blocked bootstrap writer is covered by startup timeout", func(t *testing.T) {
		outputs := newOutputSet()
		command := exec.Command(os.Args[0], "-test.run=^TestProcessSupervisorHelper$")
		command.Env = append(minimalProcessEnvironment(), "KREDOXI_PROCESS_HELPER=no-bootstrap-read")
		bootstrap := map[string]string{"value": strings.Repeat("x", 32*1024-64)}
		if _, err := devruntime.Encode(bootstrap); err != nil {
			t.Fatal("large bootstrap fixture exceeded its protocol bound")
		}
		child, _, err := startCommand(
			command, "testchild", bootstrap, true, outputs.process("testchild"), 150*time.Millisecond,
		)
		if err == nil {
			t.Fatal("blocked bootstrap was accepted as ready")
		}
		if child == nil {
			t.Fatalf("blocked bootstrap had no owned child handle: %v", err)
		}
		if !isClosed(child.finished) {
			t.Fatalf("blocked bootstrap did not time out and reap its child (startup error: %v)", err)
		}
	})

	t.Run("forced termination and listener cleanup", func(t *testing.T) {
		child, outputs, _, err := startHelper(t, "listen", "", time.Second)
		if err != nil {
			t.Fatal("listener helper failed to become ready")
		}
		data, _ := outputs.capture("testchild.stdout").snapshot()
		address := strings.TrimSpace(string(data))
		if err := child.terminate(time.Second); err != nil {
			t.Fatal("forced termination did not wait for child exit")
		}
		if !isClosed(child.finished) {
			t.Fatal("forced termination did not wait for child exit")
		}
		connection, dialErr := net.DialTimeout("tcp4", address, 150*time.Millisecond)
		if dialErr == nil {
			_ = connection.Close()
			t.Fatal("listener survived forced child termination")
		}
	})
}

func TestSupervisorTerminationContainsOwnedChild(t *testing.T) {
	command := exec.Command(os.Args[0], "-test.run=^TestProcessSupervisorHelper$")
	command.Env = append(minimalProcessEnvironment(), "KREDOXI_PROCESS_HELPER=supervisor")
	stdout, stderr := newOutputCapture(), newOutputCapture()
	supervisor, _, err := startCommand(
		command, "supervisor", struct{}{}, true,
		processOutput{stdout: stdout, stderr: stderr}, 5*time.Second,
	)
	if err != nil {
		t.Fatal("supervisor helper did not start")
	}
	t.Cleanup(func() {
		_ = supervisor.terminate(shutdownTimeout)
	})
	if !waitContainsEither(stdout, "KREDOXI_SUPERVISOR_READY ", "KREDOXI_SUPERVISOR_CHILD_START_FAILED", 15*time.Second) {
		stdoutData, _ := stdout.snapshot()
		stderrData, _ := stderr.snapshot()
		t.Fatalf("supervisor did not report its owned listener (stdout bytes: %d, stderr bytes: %d)", len(stdoutData), len(stderrData))
	}
	data, _ := stdout.snapshot()
	if bytes.Contains(data, []byte("KREDOXI_SUPERVISOR_CHILD_START_FAILED")) {
		t.Fatal("supervisor could not contain its owned child")
	}
	fields := strings.Fields(string(data))
	if len(fields) < 2 {
		t.Fatal("supervisor readiness diagnostic was malformed")
	}
	address := fields[len(fields)-1]
	if err := supervisor.terminate(shutdownTimeout); err != nil || !isClosed(supervisor.finished) {
		t.Fatal("supervisor process termination was not confirmed")
	}
	if !waitForListenerClosed(address, 5*time.Second) {
		t.Fatal("owned child listener survived supervisor termination")
	}
}

func waitContainsEither(capture *outputCapture, first, second string, timeout time.Duration) bool {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		capture.mu.Lock()
		if bytes.Contains(capture.data, []byte(first)) || bytes.Contains(capture.data, []byte(second)) {
			capture.mu.Unlock()
			return true
		}
		changed := capture.changed
		capture.mu.Unlock()
		select {
		case <-changed:
		case <-timer.C:
			return false
		}
	}
}

func waitForListenerClosed(address string, timeout time.Duration) bool {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		connection, err := net.DialTimeout("tcp4", address, 100*time.Millisecond)
		if err != nil {
			return true
		}
		_ = connection.Close()
		select {
		case <-ticker.C:
		case <-timer.C:
			return false
		}
	}
}

func TestControlAcknowledgementFailures(t *testing.T) {
	tests := []struct {
		name string
		mode string
		want string
	}{
		{"missing acknowledgement", "no-ack", "timed out"},
		{"child exits awaiting acknowledgement", "exit-on-control", "exited"},
		{"stale acknowledgement", "stale-ack", "stale"},
		{"unexpected acknowledgement operation", "wrong-operation-ack", "stale"},
		{"malformed acknowledgement", "malformed-ack", "malformed"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			child, _, _, err := startHelper(t, test.mode, "", time.Second)
			if err != nil {
				t.Fatal("helper failed to become ready")
			}
			_, err = child.control("provider-hold", 150*time.Millisecond)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				_ = child.terminate(time.Second)
				t.Fatal("invalid acknowledgement state was not rejected")
			}
			_ = child.terminate(time.Second)
		})
	}

	t.Run("duplicate acknowledgement cannot satisfy next operation", func(t *testing.T) {
		child, _, _, err := startHelper(t, "duplicate-ack", "", time.Second)
		if err != nil {
			t.Fatal("helper failed to become ready")
		}
		if ack, err := child.control("provider-hold", time.Second); err != nil || !ack.Applied {
			t.Fatal("first acknowledgement was rejected")
		}
		if _, err := child.control("provider-release", time.Second); err == nil || !strings.Contains(err.Error(), "stale") {
			_ = child.terminate(time.Second)
			t.Fatal("duplicate acknowledgement satisfied a later transition")
		}
		_ = child.terminate(time.Second)
	})
}

func TestDiagnosticRedactionDetectsInjectedLeak(t *testing.T) {
	secret := "synthetic-diagnostic-marker-7d4be6"
	child, outputs, _, err := startHelper(t, "leak", secret, time.Second)
	if err != nil {
		t.Fatal("helper failed to become ready")
	}
	if err := child.stopControlled(); err != nil {
		t.Fatal("helper shutdown failed")
	}
	if err := outputs.assertRedacted([]byte(secret)); err == nil || strings.Contains(err.Error(), secret) {
		t.Fatal("redaction check did not fail safely")
	}
	for _, stream := range []string{"testchild.stdout", "testchild.stderr"} {
		data, _ := outputs.capture(stream).snapshot()
		if !bytes.Contains(data, []byte(secret)) {
			t.Fatal("fault injection did not reach both child streams")
		}
	}
	outputs.capture("supervisor.stdout").Write([]byte(secret))
	outputs.capture("supervisor.stderr").Write([]byte(secret))
	if err := outputs.assertRedacted([]byte(secret)); err == nil || strings.Contains(err.Error(), secret) {
		t.Fatal("supervisor redaction check did not fail safely")
	}
}

func TestBrokerFailedStartupDiagnosticsAreRedacted(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatal("module root unavailable")
	}
	outputs := newOutputSet()
	fixture := &processFixture{root: root, outputs: outputs}
	t.Cleanup(func() {
		if fixture.broker != nil && !isClosed(fixture.broker.finished) {
			if err := fixture.broker.stopBroker(); err != nil {
				t.Error("broker process did not shut down cleanly")
				_ = fixture.broker.terminate(shutdownTimeout)
			}
		}
		if fixture.service != nil && !isClosed(fixture.service.finished) {
			if err := fixture.service.stopControlled(); err != nil {
				t.Error("service process did not shut down cleanly")
				_ = fixture.service.terminate(shutdownTimeout)
			}
		}
		if err := outputs.assertRedacted(fixture.secrets...); err != nil {
			t.Error("process diagnostics contained confidential material")
		}
		if !allProcessesStopped(outputs) {
			t.Error("temporary executable cleanup skipped because child exit was not confirmed")
		} else {
			if err := assertBuildDirectoryRedacted(outputs, fixture.secrets...); err != nil {
				t.Error("temporary files contained confidential material")
			}
			if err := removeBuildDirectory(outputs); err != nil {
				t.Error("test executable cleanup failed")
			}
		}
	})
	binaries, err := buildExecutables(root, outputs)
	if err != nil {
		t.Fatal("test executables failed to build")
	}
	fixture.binaries = binaries
	marker := "synthetic-bootstrap-diagnostic-marker"
	material := synthetic.TLSMaterial{PrivateKey: []byte("-----BEGIN PRIVATE KEY-----" + marker)}
	bootstrap := devruntime.BrokerBootstrap{
		TLS: material, PolicyDigest: marker, Reference: marker, Credential: marker,
	}
	child, _, err := startExecutable(
		binaries["broker"], "broker", nil, bootstrap, true, outputs.process("broker"), time.Second,
	)
	if err == nil || child == nil || !isClosed(child.finished) {
		t.Fatal("invalid bootstrap did not fail startup and reap the broker")
	}
	if err := outputs.assertRedacted([]byte(marker), material.PrivateKey, []byte("-----BEGIN PRIVATE KEY-----")); err != nil {
		t.Fatal("failed startup diagnostics leaked confidential material")
	}
}

func TestStartFailureDoesNotReturnSensitiveDiagnostics(t *testing.T) {
	secret := "secret-bootstrap-123"
	outputs := newOutputSet()
	command := exec.Command(os.Args[0], "-test.run=^TestProcessSupervisorHelper$")
	command.Env = append(minimalProcessEnvironment(), "KREDOXI_PROCESS_HELPER=crash")
	child, _, err := startCommand(command, "testchild", map[string]string{"credential": secret}, true, outputs.process("testchild"), time.Second)
	if err == nil || child == nil {
		t.Fatal("crashing test child unexpectedly started")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatal("startup error included bootstrap material")
	}
	if err := outputs.assertRedacted([]byte(secret)); err != nil {
		t.Fatal("startup diagnostics included bootstrap material")
	}
}

func TestControlOperationRejectsUnknown(t *testing.T) {
	child, _, _, err := startHelper(t, "reject", "", time.Second)
	if err != nil {
		t.Fatal("helper failed to become ready")
	}
	ack, err := child.control("unknown-operation", time.Second)
	if err != nil || ack.Applied {
		_ = child.terminate(time.Second)
		t.Fatal("unknown operation was not explicitly rejected")
	}
	if err := child.stopControlled(); err != nil {
		t.Fatal("helper shutdown failed")
	}
}

func TestProcessExitDuringControlIsNotReportedAsSuccess(t *testing.T) {
	child, _, _, err := startHelper(t, "exit-on-control", "", time.Second)
	if err != nil {
		t.Fatal("helper failed to become ready")
	}
	_, err = child.control("provider-hold", time.Second)
	if err == nil {
		t.Fatal("process exit without acknowledgement was accepted")
	}
	if err := child.wait(time.Second); err == nil {
		t.Fatal("abnormal child exit was reported as success")
	}
}

type processFixture struct {
	root                 string
	outputs              *outputSet
	binaries             map[string]string
	broker               *childProcess
	service              *childProcess
	brokerAddress        string
	serviceAddress       string
	authorizedMaterial   synthetic.TLSMaterial
	unauthorizedMaterial synthetic.TLSMaterial
	secrets              [][]byte
}

func newProcessFixture(t *testing.T) *processFixture {
	t.Helper()
	root, err := moduleRoot()
	if err != nil {
		t.Fatal("module root unavailable")
	}
	outputs := newOutputSet()
	fixture := &processFixture{root: root, outputs: outputs}
	t.Cleanup(func() {
		if fixture.broker != nil && !isClosed(fixture.broker.finished) {
			if err := fixture.broker.stopBroker(); err != nil {
				t.Error("broker process did not shut down cleanly")
				_ = fixture.broker.terminate(shutdownTimeout)
			}
		}
		if fixture.service != nil && !isClosed(fixture.service.finished) {
			if err := fixture.service.stopControlled(); err != nil {
				t.Error("service process did not shut down cleanly")
				_ = fixture.service.terminate(shutdownTimeout)
			}
		}
		if err := outputs.assertRedacted(fixture.secrets...); err != nil {
			t.Error("process diagnostics contained confidential material")
		}
		if !allProcessesStopped(outputs) {
			t.Error("temporary executable cleanup skipped because child exit was not confirmed")
		} else {
			if err := assertBuildDirectoryRedacted(outputs, fixture.secrets...); err != nil {
				t.Error("temporary files contained confidential material")
			}
			if err := removeBuildDirectory(outputs); err != nil {
				t.Error("test executable cleanup failed")
			}
		}
	})
	binaries, err := buildExecutables(root, outputs)
	if err != nil {
		t.Fatal("test executables failed to build")
	}
	fixture.binaries = binaries
	credential, err := randomCredential()
	if err != nil {
		t.Fatal("synthetic credential generation failed")
	}
	pki, err := synthetic.NewPKI()
	if err != nil {
		t.Fatal("synthetic test identity creation failed")
	}
	serverMaterial, err := pki.ServerMaterial()
	if err != nil {
		t.Fatal("synthetic server material creation failed")
	}
	authorizedMaterial, err := pki.ClientMaterial("urn:kredoxi:principal:demo-consumer")
	if err != nil {
		t.Fatal("synthetic client material creation failed")
	}
	unauthorizedMaterial, err := pki.ClientMaterial("urn:kredoxi:principal:unauthorized")
	if err != nil {
		t.Fatal("synthetic client material creation failed")
	}
	fixture.authorizedMaterial, fixture.unauthorizedMaterial = authorizedMaterial, unauthorizedMaterial
	fixture.secrets = [][]byte{[]byte(credential), []byte(examples.Reference), []byte("-----BEGIN PRIVATE KEY-----")}
	fixture.secrets = appendTLSSecrets(fixture.secrets, serverMaterial, authorizedMaterial, unauthorizedMaterial)
	service, serviceAddress, err := startService(
		binaries["service"], devruntime.ServiceBootstrap{Credential: credential}, outputs,
	)
	if err != nil {
		t.Fatal("synthetic service process failed to start")
	}
	fixture.service, fixture.serviceAddress = service, serviceAddress
	broker, brokerAddress, err := startBroker(
		binaries["broker"], makeBrokerBootstrap(serverMaterial, credential), outputs,
	)
	if err != nil {
		t.Fatal("broker process failed to start")
	}
	fixture.broker, fixture.brokerAddress = broker, brokerAddress
	return fixture
}

func (f *processFixture) consumer(t *testing.T, material synthetic.TLSMaterial, expectedFailure string) *childProcess {
	t.Helper()
	child, err := startConsumer(
		f.binaries["consumer"], f.root, material, f.brokerAddress,
		f.serviceAddress, expectedFailure, f.outputs,
	)
	if err != nil {
		t.Fatal("consumer process failed to become ready")
	}
	return child
}

func releaseConsumer(t *testing.T, child *childProcess) {
	t.Helper()
	ack, err := child.control("resolve", controlTimeout)
	if err != nil || !ack.Applied {
		_ = child.terminate(shutdownTimeout)
		t.Fatal("consumer resolution gate was not acknowledged")
	}
	if err := child.closeInput(); err != nil {
		_ = child.terminate(shutdownTimeout)
		t.Fatal("consumer control input did not close")
	}
}

func TestConsumerKilledBeforeResolution(t *testing.T) {
	fixture := newProcessFixture(t)
	child := fixture.consumer(t, fixture.authorizedMaterial, "")
	if err := child.terminate(shutdownTimeout); err != nil || !isClosed(child.finished) {
		t.Fatal("consumer termination was not confirmed")
	}
	ack, err := fixture.broker.control("provider-idle", controlTimeout)
	if err != nil || !ack.Applied {
		t.Fatal("pre-resolution termination reached the provider")
	}
}

func TestConsumerKilledDuringResolutionDoesNotReleaseToAnotherPrincipal(t *testing.T) {
	fixture := newProcessFixture(t)
	if err := fixture.broker.requireApplied("provider-hold", controlTimeout); err != nil {
		t.Fatal("synthetic provider hold was not applied")
	}
	child := fixture.consumer(t, fixture.authorizedMaterial, "")
	releaseConsumer(t, child)
	if err := fixture.broker.requireApplied("await-provider", 11*time.Second); err != nil {
		t.Fatal("provider did not observe the authorized request")
	}
	if err := child.terminate(shutdownTimeout); err != nil {
		t.Fatal("consumer termination was not confirmed")
	}
	if err := fixture.broker.requireApplied("provider-release", controlTimeout); err != nil {
		t.Fatal("synthetic provider did not resume")
	}
	if !fixture.outputs.capture("broker.stdout").waitContains(`"status":"canceled"`, 3*time.Second) {
		t.Fatal("canceled request was not observed by the broker")
	}
	other := fixture.consumer(t, fixture.unauthorizedMaterial, "policy_denied")
	releaseConsumer(t, other)
	if err := other.wait(5 * time.Second); err != nil {
		t.Fatal("unauthorized follow-up consumer did not fail safely")
	}
}

func TestBrokerKilledWithAuthorizedClientActive(t *testing.T) {
	fixture := newProcessFixture(t)
	if err := fixture.broker.requireApplied("provider-hold", controlTimeout); err != nil {
		t.Fatal("synthetic provider hold was not applied")
	}
	child := fixture.consumer(t, fixture.authorizedMaterial, "broker_unavailable")
	releaseConsumer(t, child)
	if err := fixture.broker.requireApplied("await-provider", 11*time.Second); err != nil {
		t.Fatal("authorized request did not reach provider")
	}
	address := fixture.brokerAddress
	if err := fixture.broker.terminate(shutdownTimeout); err != nil {
		t.Fatal("broker process termination was not confirmed")
	}
	if err := child.wait(10 * time.Second); err != nil {
		t.Fatal("active consumer did not report broker_unavailable")
	}
	connection, err := net.DialTimeout("tcp4", address, 150*time.Millisecond)
	if err == nil {
		_ = connection.Close()
		t.Fatal("broker listener survived process termination")
	}
}

func TestBrokerDeathWhileSupervisorAwaitsControlAcknowledgement(t *testing.T) {
	fixture := newProcessFixture(t)
	sent := make(chan struct{})
	controlResult := make(chan error, 1)
	go func() {
		_, err := fixture.broker.controlWithSent("await-provider", 10*time.Second, sent)
		controlResult <- err
	}()
	select {
	case <-sent:
	case <-time.After(time.Second):
		t.Fatal("control command was not written")
	}
	if err := fixture.broker.terminate(shutdownTimeout); err != nil {
		t.Fatal("broker termination was not confirmed")
	}
	select {
	case err := <-controlResult:
		if err == nil || !strings.Contains(err.Error(), "exited") {
			t.Fatal("broker exit while awaiting acknowledgement was not reported")
		}
	case <-time.After(time.Second):
		t.Fatal("control waiter remained blocked after broker exit")
	}
}

func TestBrokerControlAcknowledgesAppliedStateAndRejectsUnknown(t *testing.T) {
	fixture := newProcessFixture(t)
	unknown, err := fixture.broker.control("unknown-operation", controlTimeout)
	if err != nil || unknown.Applied {
		t.Fatal("broker did not explicitly reject unknown control")
	}
	if err := fixture.broker.requireApplied("provider-unavailable", controlTimeout); err != nil {
		t.Fatal("broker did not acknowledge provider-unavailable state")
	}
	unavailable := fixture.consumer(t, fixture.authorizedMaterial, "provider_unavailable")
	releaseConsumer(t, unavailable)
	if err := unavailable.wait(5 * time.Second); err != nil {
		t.Fatal("consumer did not observe the applied unavailable state")
	}
	if err := fixture.broker.requireApplied("provider-available", controlTimeout); err != nil {
		t.Fatal("broker did not acknowledge provider-available state")
	}
	available := fixture.consumer(t, fixture.authorizedMaterial, "")
	releaseConsumer(t, available)
	if err := available.wait(10 * time.Second); err != nil {
		t.Fatal("consumer did not observe the restored provider state")
	}
}

func TestSyntheticServiceTerminationFailsConsumerAuthentication(t *testing.T) {
	fixture := newProcessFixture(t)
	if err := fixture.service.terminate(shutdownTimeout); err != nil {
		t.Fatal("service process termination was not confirmed")
	}
	child := fixture.consumer(t, fixture.authorizedMaterial, "consumer_authentication_failed")
	releaseConsumer(t, child)
	if err := child.wait(10 * time.Second); err != nil {
		t.Fatal("consumer did not fail synthetic service authentication")
	}
	if !isClosed(fixture.broker.finished) {
		ack, err := fixture.broker.control("provider-idle", controlTimeout)
		if err != nil || !ack.Applied {
			t.Fatal("broker did not survive service termination")
		}
	}
}

func TestConcurrentConsumersRemainPrincipalIsolated(t *testing.T) {
	fixture := newProcessFixture(t)
	denied := fixture.consumer(t, fixture.unauthorizedMaterial, "policy_denied")
	allowed := fixture.consumer(t, fixture.authorizedMaterial, "")
	releaseConsumer(t, denied)
	releaseConsumer(t, allowed)
	if err := denied.wait(5 * time.Second); err != nil {
		t.Fatal("unauthorized concurrent consumer did not remain denied")
	}
	if err := allowed.wait(10 * time.Second); err != nil {
		t.Fatal("authorized concurrent consumer did not complete")
	}
}

func TestSyntheticProviderDeadlineIsBoundedAndContextAware(t *testing.T) {
	fixture := newProcessFixture(t)
	if err := fixture.broker.requireApplied("provider-hold", controlTimeout); err != nil {
		t.Fatal("synthetic provider hold was not applied")
	}
	child := fixture.consumer(t, fixture.authorizedMaterial, "")
	releaseConsumer(t, child)
	if err := fixture.broker.requireApplied("await-provider", 11*time.Second); err != nil {
		t.Fatal("request did not enter the synthetic provider")
	}
	if err := child.wait(5 * time.Second); err == nil {
		t.Fatal("consumer unexpectedly received a credential from a held provider")
	}
	if !fixture.outputs.capture("broker.stdout").waitContains(`"status":"canceled"`, 3*time.Second) {
		t.Fatal("broker did not enforce the synthetic provider request deadline")
	}
	if err := fixture.broker.requireApplied("provider-release", controlTimeout); err != nil {
		t.Fatal("synthetic provider did not resume after the request deadline")
	}
}
