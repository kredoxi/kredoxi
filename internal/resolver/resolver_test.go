package resolver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kredoxi/kredoxi/examples"
	"github.com/kredoxi/kredoxi/internal/synthetic"
)

type fixture struct {
	broker   *Broker
	client   *Client
	provider *SyntheticProvider
	pki      *synthetic.PKI
	config   *tls.Config
	log      *bytes.Buffer
}

func setup(t *testing.T) *fixture {
	t.Helper()
	pki, err := synthetic.NewPKI()
	if err != nil {
		t.Fatal(err)
	}
	serverConfig, err := pki.ServerConfig()
	if err != nil {
		t.Fatal(err)
	}
	config, err := pki.ClientConfig(examples.Principal)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := NewPolicy(examples.Policy, sha256.Sum256([]byte(examples.TrustedPolicy)))
	if err != nil {
		t.Fatal(err)
	}
	provider, err := NewSyntheticProvider([]string{examples.Reference})
	if err != nil {
		t.Fatal(err)
	}
	log := &bytes.Buffer{}
	telemetry, err := NewTelemetry(log)
	if err != nil {
		t.Fatal(err)
	}
	broker, err := Start(serverConfig, policy, provider, telemetry)
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(broker.Address(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		client.Close()
		if err := broker.Close(); err != nil && !errors.Is(err, TelemetryUnavailable) {
			t.Error(err)
		}
	})
	return &fixture{broker, client, provider, pki, config, log}
}

func expectCategory(t *testing.T, got, want error) {
	t.Helper()
	if !errors.Is(got, want) {
		t.Fatalf("category mismatch: got %v, want %v", got, want)
	}
}

func TestReferences(t *testing.T) {
	for _, text := range []string{
		"", "password", "kredoxi://database/production/password", "KREDOXI://v1/demo/example/password",
		examples.Reference + "/", examples.Reference + "?x=1", examples.Reference + "#secret",
		"kredoxi://v1/demo/../password", "kredoxi://v1/demo/%2e%2e/password",
		"kredoxi://v1/demo/example%2fother/password", "kredoxi://v2/demo/example/password",
		"kredoxi://v1/demo/exämple/password", "kredoxi://v1/demo/example/password\n",
		"kredoxi://v1/demo\\example/password", "kredoxi://v1/user@demo/example/password",
		"kredoxi://v1/demo/example/password\x00", "kredoxi://v1/demo/example/" + strings.Repeat("a", 33),
	} {
		t.Run(text, func(t *testing.T) { _, err := ParseReference(text); expectCategory(t, err, InvalidReference) })
	}
	ref, err := ParseReference(examples.Reference)
	if err != nil || ref.String() != examples.Reference {
		t.Fatal("canonical reference failed")
	}
}

func TestPolicyIntegrityAndImmutability(t *testing.T) {
	digest := sha256.Sum256([]byte(examples.TrustedPolicy))
	policy, err := NewPolicy(examples.Policy, digest)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := ParseReference(examples.Reference)
	if err != nil {
		t.Fatal(err)
	}
	if !policy.permits(examples.Principal, ref) || policy.permits("urn:kredoxi:principal:other", ref) {
		t.Fatal("exact policy failed")
	}
	tampered := bytes.ReplaceAll(examples.Policy, []byte("demo-consumer"), []byte("other"))
	_, err = NewPolicy(tampered, digest)
	expectCategory(t, err, PolicyIntegrity)
	for _, text := range []string{
		`{"version":1,"version":1,"allow":{}}`, `{"Version":1,"allow":{}}`,
		`{"version":1,"allow":null}`, `{"version":2,"allow":{}}`,
		`{"version":1,"allow":{"urn:kredoxi:principal:x":["kredoxi://v1/a/b/c","kredoxi://v1/a/b/c"]}}`,
		`{"version":1,"allow":{"urn:kredoxi:principal:x":[],"urn:kredoxi:principal:x":[]}}`,
		`{"version":1,"allow":{"claimed-process":[]}}`,
		`{"version":1,"allow":{"urn:kredoxi:principal:x":["../secret"]}}`,
		`{"version":1,"allow":{},"unknown":true}`,
	} {
		t.Run(text, func(t *testing.T) {
			_, err := NewPolicy([]byte(text), sha256.Sum256([]byte(text)))
			expectCategory(t, err, InvalidPolicy)
		})
	}
	copied := append([]byte(nil), examples.Policy...)
	policy, err = NewPolicy(copied, digest)
	if err != nil {
		t.Fatal(err)
	}
	for i := range copied {
		copied[i] = 'x'
	}
	if !policy.permits(examples.Principal, ref) {
		t.Fatal("mutable input changed policy")
	}
}

func TestResolutionConsumerAndFailures(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	value, err := f.client.Resolve(ctx, examples.Reference)
	if err != nil || len(value) != 64 {
		t.Fatal("resolution failed")
	}
	if bytes.Contains(examples.Consumer, []byte(value)) || !bytes.Contains(examples.Consumer, []byte(examples.Reference)) {
		t.Fatal("configuration exposure")
	}
	err = Consume(ctx, f.client, examples.Consumer, func(got string) error {
		if got != value {
			return errors.New("different_credential")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var stolen string
	err = Consume(ctx, f.client, examples.Consumer, func(got string) error { stolen = got; return nil })
	if err != nil || stolen != value {
		t.Fatal("authorized-process limitation not demonstrated")
	}
	_, err = f.client.Resolve(ctx, "kredoxi://v1/demo/example/other")
	expectCategory(t, err, PolicyDenied)
	f.provider.SetAvailable(false)
	_, err = f.client.Resolve(ctx, examples.Reference)
	expectCategory(t, err, ProviderUnavailable)
	f.provider.SetAvailable(true)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = f.client.Resolve(ctx, examples.Reference)
	expectCategory(t, err, Canceled)
	if err := f.broker.Close(); err != nil {
		t.Fatal(err)
	}
	_, err = f.client.Resolve(context.Background(), examples.Reference)
	expectCategory(t, err, BrokerUnavailable)
	log := f.log.String()
	if strings.Contains(log, value) || strings.Contains(log, examples.Reference) ||
		strings.Contains(log, examples.Principal) {
		t.Fatal("telemetry leaked sensitive fields")
	}
	events := strings.Split(strings.TrimSpace(log), "\n")
	for _, line := range events {
		var event Event
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatal(err)
		}
		if event.SchemaVersion != 1 || event.AgentVersion != Version || len(event.RequestID) != 32 {
			t.Fatal("event schema mismatch")
		}
	}
}

func (f *fixture) raw(t *testing.T, body string, config *tls.Config, headers map[string]string) (int, []byte) {
	t.Helper()
	transport := &http.Transport{TLSClientConfig: config, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	req, err := http.NewRequest(http.MethodPost, "https://"+f.broker.Address()+"/v1/resolve", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	res, err := client.Do(req)
	if err != nil {
		return 0, nil
	}
	defer func() {
		if err := res.Body.Close(); err != nil {
			t.Error(err)
		}
	}()
	data, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return res.StatusCode, data
}

func TestAuthenticationBoundaries(t *testing.T) {
	f := setup(t)
	body := `{"reference":"` + examples.Reference + `"}`
	denied, err := f.pki.ClientConfig("urn:kredoxi:principal:unauthorized")
	if err != nil {
		t.Fatal(err)
	}
	status, data := f.raw(t, body, denied, map[string]string{"X-Principal": examples.Principal})
	if status != 403 || !bytes.Contains(data, []byte("policy_denied")) {
		t.Fatal("claimed identity trusted")
	}
	noCert := f.config.Clone()
	noCert.Certificates = nil
	status, _ = f.raw(t, body, noCert, nil)
	if status != 0 {
		t.Fatal("anonymous TLS accepted")
	}
	otherPKI, err := synthetic.NewPKI()
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := otherPKI.ClientConfig(examples.Principal)
	if err != nil {
		t.Fatal(err)
	}
	foreign.RootCAs = f.config.RootCAs
	status, _ = f.raw(t, body, foreign, nil)
	if status != 0 {
		t.Fatal("foreign issuer accepted")
	}
	badIdentity, err := f.pki.ClientConfig("urn:kredoxi:principal:demo-consumer?claimed=true")
	if err != nil {
		t.Fatal(err)
	}
	status, _ = f.raw(t, body, badIdentity, nil)
	if status != 401 {
		t.Fatal("ambiguous SAN accepted")
	}
	oldTLS := f.config.Clone()
	oldTLS.MinVersion, oldTLS.MaxVersion = tls.VersionTLS12, tls.VersionTLS12
	status, _ = f.raw(t, body, oldTLS, nil)
	if status != 0 {
		t.Fatal("TLS downgrade accepted")
	}
	wrongServerRoots := f.config.Clone()
	wrongServerRoots.RootCAs = foreign.RootCAs
	// New independent CA roots cannot authenticate the broker.
	wrongServerRoots, err = otherPKI.ClientConfig(examples.Principal)
	if err != nil {
		t.Fatal(err)
	}
	status, _ = f.raw(t, body, wrongServerRoots, nil)
	if status != 0 {
		t.Fatal("server impersonation accepted")
	}
}

func TestMalformedRequests(t *testing.T) {
	f := setup(t)
	for _, body := range []string{
		"", "null", "[]", "{", `{"Reference":"` + examples.Reference + `"}`,
		`{"reference":"` + examples.Reference + `","reference":"` + examples.Reference + `"}`,
		`{"reference":"` + examples.Reference + `","principal":"` + examples.Principal + `"}`,
		`{"reference":123}`, `{"reference":null}`, `{"reference":"../password"}`,
		`{"reference":"` + examples.Reference + `"} {}`, strings.Repeat(" ", 1025),
		"{\"reference\":\"\xff\"}",
	} {
		t.Run(body, func(t *testing.T) {
			status, data := f.raw(t, body, f.config, nil)
			if status != 400 || bytes.Contains(data, []byte(`"value"`)) {
				t.Fatal("malformed request accepted")
			}
		})
	}
	status, _ := f.raw(t, `{"reference":"`+examples.Reference+`"}`, f.config, map[string]string{"Content-Encoding": "gzip"})
	if status != 400 {
		t.Fatal("encoded request accepted")
	}
}

func TestUnknownSecretAndProviderDiagnostics(t *testing.T) {
	f := setup(t)
	empty, err := NewSyntheticProvider(nil)
	if err != nil {
		t.Fatal(err)
	}
	f.broker.provider = empty
	_, err = f.client.Resolve(context.Background(), examples.Reference)
	expectCategory(t, err, SecretNotFound)
	f.broker.provider = diagnosticProvider{}
	_, err = f.client.Resolve(context.Background(), examples.Reference)
	expectCategory(t, err, ProviderUnavailable)
	if strings.Contains(f.log.String(), "provider-sensitive-diagnostic") {
		t.Fatal("provider diagnostics leaked")
	}
}

type countingNotFoundProvider struct{ calls atomic.Int32 }

func (p *countingNotFoundProvider) Resolve(context.Context, Reference) (string, error) {
	p.calls.Add(1)
	return "", SecretNotFound
}

func TestPolicyDenialPrecedesProviderLookup(t *testing.T) {
	f := setup(t)
	provider := &countingNotFoundProvider{}
	f.broker.provider = provider
	deniedTLS, err := f.pki.ClientConfig("urn:kredoxi:principal:unauthorized")
	if err != nil {
		t.Fatal(err)
	}
	denied, err := NewClient(f.broker.Address(), deniedTLS)
	if err != nil {
		t.Fatal(err)
	}
	defer denied.Close()
	_, err = denied.Resolve(context.Background(), examples.Reference)
	expectCategory(t, err, PolicyDenied)
	_, err = denied.Resolve(context.Background(), "kredoxi://v1/demo/example/missing")
	expectCategory(t, err, PolicyDenied)
	if got := provider.calls.Load(); got != 0 {
		t.Fatalf("unauthorized reference caused %d provider lookups", got)
	}
}

func TestAuthorizedMissingReferenceIsDistinguishable(t *testing.T) {
	f := setup(t)
	missing := "kredoxi://v1/demo/example/missing"
	document := []byte(`{"version":1,"allow":{"urn:kredoxi:principal:demo-consumer":["` + missing + `"]}}`)
	policy, err := NewPolicy(document, sha256.Sum256(document))
	if err != nil {
		t.Fatal(err)
	}
	f.broker.policy = policy
	provider := &countingNotFoundProvider{}
	f.broker.provider = provider
	_, err = f.client.Resolve(context.Background(), missing)
	expectCategory(t, err, SecretNotFound)
	if got := provider.calls.Load(); got != 1 {
		t.Fatalf("authorized exact reference caused %d provider lookups", got)
	}
}

type diagnosticProvider struct{}

func (diagnosticProvider) Resolve(context.Context, Reference) (string, error) {
	return "", errors.New("provider-sensitive-diagnostic")
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("sink-sensitive-diagnostic") }

func TestTelemetryFailureIsSticky(t *testing.T) {
	f := setup(t)
	f.broker.telemetry.mu.Lock()
	f.broker.telemetry.writer = failingWriter{}
	f.broker.telemetry.mu.Unlock()
	value, err := f.client.Resolve(context.Background(), examples.Reference)
	expectCategory(t, err, TelemetryUnavailable)
	if value != "" {
		t.Fatal("value released without audit")
	}
	f.broker.telemetry.mu.Lock()
	f.broker.telemetry.writer = f.log
	f.broker.telemetry.mu.Unlock()
	value, err = f.client.Resolve(context.Background(), examples.Reference)
	expectCategory(t, err, TelemetryUnavailable)
	if value != "" {
		t.Fatal("telemetry failure silently recovered")
	}
}

type shortWriter struct{}

func (shortWriter) Write(data []byte) (int, error) { return len(data) - 1, nil }

func TestAuditShortWrite(t *testing.T) {
	telemetry, err := NewTelemetry(shortWriter{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = telemetry.emit("resolved", examples.Principal, examples.Reference)
	expectCategory(t, err, TelemetryUnavailable)
	if telemetry.healthy() {
		t.Fatal("short write accepted")
	}
}

func TestMalformedBrokerResponses(t *testing.T) {
	pki, err := synthetic.NewPKI()
	if err != nil {
		t.Fatal(err)
	}
	serverTLS, err := pki.ServerConfig()
	if err != nil {
		t.Fatal(err)
	}
	clientTLS, err := pki.ClientConfig(examples.Principal)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, body string
		status     int
	}{
		{"duplicate", `{"value":"x","value":"y","request_id":"x"}`, 200},
		{"unknown", `{"value":"x","request_id":"x","extra":true}`, 200},
		{"missing", `{}`, 200},
		{"oversized", strings.Repeat(" ", 2049), 200},
		{"error-with-value", `{"value":"x","error":"policy_denied","request_id":"x"}`, 403},
		{"unknown-error", `{"error":"private-provider-error","request_id":"x"}`, 503},
		{"redirect", `{}`, 302},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Cache-Control", "no-store")
				if test.status == 302 {
					w.Header().Set("Location", "https://attacker.invalid/")
				}
				w.WriteHeader(test.status)
				if _, err := io.WriteString(w, test.body); err != nil {
					t.Error(err)
				}
			}))
			server.TLS = serverTLS.Clone()
			server.StartTLS()
			defer server.Close()
			client, err := NewClient(server.Listener.Addr().String(), clientTLS)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			value, err := client.Resolve(context.Background(), examples.Reference)
			if err == nil || value != "" {
				t.Fatal("malformed response accepted")
			}
		})
	}
}
func TestConcurrentIsolationAndRepeatedAccess(t *testing.T) {
	f := setup(t)
	deniedTLS, err := f.pki.ClientConfig("urn:kredoxi:principal:unauthorized")
	if err != nil {
		t.Fatal(err)
	}
	denied, err := NewClient(f.broker.Address(), deniedTLS)
	if err != nil {
		t.Fatal(err)
	}
	defer denied.Close()
	expected, err := f.client.Resolve(context.Background(), examples.Reference)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 5; j++ {
				if i%2 == 0 {
					got, err := f.client.Resolve(context.Background(), examples.Reference)
					if err != nil || got != expected {
						t.Error("authorized request confused")
					}
				} else {
					got, err := denied.Resolve(context.Background(), examples.Reference)
					if !errors.Is(err, PolicyDenied) || got != "" {
						t.Error("cross-client leakage")
					}
				}
			}
		}(i)
	}
	wg.Wait()
	if err := f.broker.Close(); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(f.log.String()), "\n") {
		var event Event
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatal(err)
		}
		if seen[event.RequestID] {
			t.Fatal("request ID reused")
		}
		seen[event.RequestID] = true
	}
	if len(seen) != 33 {
		t.Fatalf("missing access events: %d", len(seen))
	}
}

func TestInputConfigurationAndClientSafety(t *testing.T) {
	f := setup(t)
	for _, address := range []string{"localhost:443", "0.0.0.0:443", "127.0.0.1:0", "127.0.0.1:65536", "attacker.invalid:443"} {
		_, err := NewClient(address, f.config)
		expectCategory(t, err, InvalidRequest)
	}
	insecure := f.config.Clone()
	insecure.InsecureSkipVerify = true
	_, err := NewClient(f.broker.Address(), insecure)
	expectCategory(t, err, InvalidRequest)
	for _, config := range []string{`{"credential":"actual-value"}`, `{"credential":"` + examples.Reference + `","principal":"trusted"}`, `{"Credential":"` + examples.Reference + `"}`} {
		called := false
		err := Consume(context.Background(), f.client, []byte(config), func(string) error { called = true; return nil })
		if err == nil || called {
			t.Fatal("unsafe config accepted")
		}
	}
}

func TestConnectionLimitShutdown(t *testing.T) {
	f := setup(t)
	var connections []net.Conn
	for i := 0; i < 16; i++ {
		connection, err := net.DialTimeout("tcp", f.broker.Address(), time.Second)
		if err != nil {
			t.Fatal(err)
		}
		connections = append(connections, connection)
	}
	for _, connection := range connections {
		if err := connection.Close(); err != nil {
			t.Error(err)
		}
	}
	if err := f.broker.Close(); err != nil {
		t.Fatal(err)
	}
}

func FuzzReference(f *testing.F) {
	f.Add(examples.Reference)
	f.Add("../password")
	f.Fuzz(func(t *testing.T, text string) {
		ref, err := ParseReference(text)
		if err == nil && (ref.String() != text || len(text) > 128) {
			t.Fatal("noncanonical parser output")
		}
	})
}

func FuzzRequestJSON(f *testing.F) {
	f.Add([]byte(`{"reference":"` + examples.Reference + `"}`))
	f.Add([]byte(`{"reference":null}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var input request
		err := strictJSON(data, 1024, []string{"reference"}, &input)
		if err == nil && len(data) > 1024 {
			t.Fatal("unbounded JSON accepted")
		}
	})
}
