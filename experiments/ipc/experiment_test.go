package ipc

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/kredoxi/kredoxi/examples"
	"github.com/kredoxi/kredoxi/internal/resolver"
	"github.com/kredoxi/kredoxi/internal/synthetic"
)

func TestIPCProcessHelper(t *testing.T) {
	mode := os.Getenv("KREDOXI_IPC_EXPERIMENT_HELPER")
	if mode == "" {
		return
	}
	switch mode {
	case "mtls":
		runMTLSHelper(t)
	case "native":
		runNativeIPCHelper(t)
	default:
		t.Fatal("unknown experiment helper mode")
	}
}

func TestCopiedSyntheticMTLSKeyWorksInSeparateProcess(t *testing.T) {
	value, err := randomSyntheticValue()
	if err != nil {
		t.Fatal("could not create synthetic mTLS test value")
	}
	pki, broker, telemetryOutput := startMTLSBaseline(t, value)
	material, err := pki.ClientMaterial(examples.Principal)
	if err != nil {
		t.Fatal("could not create synthetic client key")
	}
	input, err := json.Marshal(struct {
		Material  synthetic.TLSMaterial `json:"material"`
		Reference string                `json:"reference"`
	}{Material: material, Reference: examples.Reference})
	if err != nil {
		t.Fatal("could not encode in-memory test material")
	}
	result := runHelper(t, "mtls", map[string]string{
		"KREDOXI_IPC_ADDRESS": broker.Address(),
	}, input)
	if result.err != nil || !strings.Contains(result.stdout, "ipc-helper:mtls=resolved") {
		t.Fatal("a separate process could not use the copied synthetic mTLS key")
	}
	assertOutputDoesNotContain(t, result.stdout+result.stderr, material.PrivateKey)
	assertOutputDoesNotContain(t, result.stdout+result.stderr, []byte(value))
	assertOutputDoesNotContain(t, telemetryOutput.String(), material.PrivateKey)
	assertOutputDoesNotContain(t, telemetryOutput.String(), []byte(value))
}

func startMTLSBaseline(t *testing.T, value string) (*synthetic.PKI, *resolver.Broker, *bytes.Buffer) {
	t.Helper()
	pki, err := synthetic.NewPKI()
	if err != nil {
		t.Fatal("could not create ephemeral test PKI")
	}
	serverTLS, err := pki.ServerConfig()
	if err != nil {
		t.Fatal("could not create synthetic server certificate")
	}
	policy, err := resolver.NewPolicy(
		examples.Policy,
		sha256.Sum256([]byte(examples.TrustedPolicy)),
	)
	if err != nil {
		t.Fatal("could not create synthetic policy")
	}
	provider, err := resolver.NewSyntheticProviderWithValues(map[string]string{examples.Reference: value})
	if err != nil {
		t.Fatal("could not create synthetic provider")
	}
	var telemetryOutput bytes.Buffer
	telemetry, err := resolver.NewTelemetry(&telemetryOutput)
	if err != nil {
		t.Fatal("could not create telemetry")
	}
	broker, err := resolver.Start(serverTLS, policy, provider, telemetry)
	if err != nil {
		t.Fatal("could not start unchanged mTLS baseline")
	}
	t.Cleanup(func() {
		if err := broker.Close(); err != nil {
			t.Error("mTLS baseline did not stop cleanly")
		}
	})
	return pki, broker, &telemetryOutput
}

func TestRequestValidationAndAuthorizationOrder(t *testing.T) {
	broker := newExperimentBroker("uid:authorized", testReference, "synthetic-value")

	for _, raw := range []string{
		"", "null", "[]", "{", `{"reference":"` + testReference + `","reference":"` + testReference + `"}`,
		`{"Reference":"` + testReference + `"}`, `{"reference":"` + testReference + `"} {}`,
		strings.Repeat("x", maxRequestBytes+1), `{"reference":null}`,
	} {
		if got := broker.resolve("uid:authorized", []byte(raw)).Status; got != "invalid_request" {
			t.Fatalf("malformed request status was %q", got)
		}
	}
	if got := broker.resolve("uid:authorized", []byte(`{"reference":"kredoxi://v1/demo/other/password"}`)).Status; got != "policy_denied" {
		t.Fatalf("unauthorized reference status was %q", got)
	}
	if got := broker.lookups.Load(); got != 0 {
		t.Fatalf("unauthorized requests caused %d provider lookups", got)
	}

	missing := "kredoxi://v1/demo/example/missing"
	broker.allowed["uid:authorized"][missing] = true
	if got := broker.resolve("uid:authorized", []byte(`{"reference":"`+missing+`"}`)).Status; got != "secret_not_found" {
		t.Fatalf("authorized missing reference status was %q", got)
	}
	if got := broker.lookups.Load(); got != 1 {
		t.Fatalf("authorized missing reference caused %d provider lookups", got)
	}
}

type helperResult struct {
	stdout string
	stderr string
	err    error
}

func runHelper(t *testing.T, mode string, extraEnv map[string]string, stdin []byte) helperResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestIPCProcessHelper$")
	cmd.Env = helperEnvironment(mode, extraEnv)
	cmd.Stdin = bytes.NewReader(stdin)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		err = errors.New("experiment helper exceeded its 10-second bound")
	}
	return helperResult{stdout: stdout.String(), stderr: stderr.String(), err: err}
}

func helperEnvironment(mode string, extra map[string]string) []string {
	names := []string{"PATH", "SystemRoot", "WINDIR", "TEMP", "TMP"}
	env := make([]string, 0, len(names)+len(extra)+1)
	for _, name := range names {
		if value, ok := os.LookupEnv(name); ok {
			env = append(env, name+"="+value)
		}
	}
	env = append(env, "KREDOXI_IPC_EXPERIMENT_HELPER="+mode)
	for name, value := range extra {
		env = append(env, name+"="+value)
	}
	return env
}

func assertOutputDoesNotContain(t *testing.T, output string, sensitive []byte) {
	t.Helper()
	if len(sensitive) != 0 && strings.Contains(output, string(sensitive)) {
		t.Fatal("experiment output contained synthetic private-key material")
	}
}

func runMTLSHelper(t *testing.T) {
	t.Helper()
	data, err := io.ReadAll(io.LimitReader(os.Stdin, 16*1024+1))
	if err != nil || len(data) == 0 || len(data) > 16*1024 {
		t.Fatal("mTLS helper received invalid bounded input")
	}
	var input struct {
		Material  synthetic.TLSMaterial `json:"material"`
		Reference string                `json:"reference"`
	}
	if err := json.Unmarshal(data, &input); err != nil {
		t.Fatal("mTLS helper could not parse synthetic test material")
	}
	config, err := synthetic.ClientConfigFromMaterial(input.Material)
	if err != nil {
		t.Fatal("mTLS helper could not load synthetic test material")
	}
	client, err := resolver.NewClient(os.Getenv("KREDOXI_IPC_ADDRESS"), config)
	if err != nil {
		t.Fatal("mTLS helper could not create the baseline client")
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	value, err := client.Resolve(ctx, input.Reference)
	if err != nil || len(value) != 64 {
		t.Fatal("mTLS helper did not resolve through the unchanged baseline")
	}
	_, err = io.WriteString(os.Stdout, "ipc-helper:mtls=resolved\n")
	if err != nil {
		t.Fatal("mTLS helper could not report bounded evidence")
	}
}
