package resolver

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"
)

const maxBody = 1024
const operationTimeout = 2 * time.Second

type request struct {
	Reference string `json:"reference"`
}
type response struct {
	Value     string `json:"value,omitempty"`
	Error     string `json:"error,omitempty"`
	RequestID string `json:"request_id"`
}

type Broker struct {
	policy    *Policy
	provider  Provider
	telemetry *Telemetry
	server    *http.Server
	listener  net.Listener
	done      chan error
	active    chan struct{}
	closeOnce sync.Once
	closeErr  error
}

// Start uses only a dedicated caller-supplied private CA. No system roots or
// client-controlled identity header participates in authentication.
func Start(config *tls.Config, policy *Policy, provider Provider, telemetry *Telemetry) (*Broker, error) {
	if config == nil || config.ClientCAs == nil || len(config.Certificates) != 1 ||
		policy == nil || provider == nil || telemetry == nil {
		return nil, InvalidRequest
	}
	secure := config.Clone()
	secure.MinVersion, secure.MaxVersion = tls.VersionTLS13, tls.VersionTLS13
	secure.ClientAuth = tls.RequireAndVerifyClientCert
	secure.SessionTicketsDisabled = true
	secure.NextProtos = []string{"http/1.1"}
	// Dynamic config callbacks could replace the enforced security settings.
	if secure.GetConfigForClient != nil || secure.GetCertificate != nil ||
		secure.InsecureSkipVerify || secure.KeyLogWriter != nil {
		return nil, InvalidRequest
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, BrokerUnavailable
	}
	broker := &Broker{
		policy: policy, provider: provider, telemetry: telemetry,
		listener: tls.NewListener(&limitedListener{
			Listener: listener, slots: make(chan struct{}, 16), closed: make(chan struct{}),
		}, secure), done: make(chan error, 1),
		active: make(chan struct{}, 8),
	}
	broker.server = &http.Server{
		Handler: http.HandlerFunc(broker.handle), TLSConfig: secure,
		ReadHeaderTimeout: time.Second, ReadTimeout: 2 * time.Second,
		WriteTimeout: 4 * time.Second, IdleTimeout: 2 * time.Second, MaxHeaderBytes: 4096,
		ErrorLog: log.New(transportLog{telemetry}, "", 0),
	}
	if _, err := telemetry.emit("started", "", ""); err != nil {
		if closeErr := listener.Close(); closeErr != nil {
			return nil, InternalFailure
		}
		return nil, err
	}
	go func() {
		err := broker.server.Serve(broker.listener)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		broker.done <- err
	}()
	return broker, nil
}

func (b *Broker) Address() string { return b.listener.Addr().String() }

func (b *Broker) Close() error {
	b.closeOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		b.closeErr = b.server.Shutdown(ctx)
		if b.closeErr != nil {
			if err := b.server.Close(); err != nil {
				b.closeErr = InternalFailure
			}
		}
		if err := <-b.done; err != nil {
			b.closeErr = BrokerUnavailable
		}
		if _, err := b.telemetry.emit("stopped", "", ""); err != nil {
			b.closeErr = err
		}
	})
	return b.closeErr
}

type transportLog struct{ telemetry *Telemetry }

func (l transportLog) Write(data []byte) (int, error) {
	// TLS diagnostics can contain attacker-controlled certificate names; discard
	// their text, but emit a bounded, non-sensitive event instead.
	if _, err := l.telemetry.emit("transport_failure", "", ""); err != nil {
		return 0, err
	}
	return len(data), nil
}

func principal(r *http.Request) (string, error) {
	if r.TLS == nil || r.TLS.Version != tls.VersionTLS13 ||
		len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
		return "", AuthenticationDenied
	}
	certificate := r.TLS.PeerCertificates[0]
	if len(certificate.URIs) != 1 {
		return "", AuthenticationDenied
	}
	identity := certificate.URIs[0].String()
	if !principalPattern.MatchString(identity) {
		return "", AuthenticationDenied
	}
	return identity, nil
}

func (b *Broker) handle(w http.ResponseWriter, r *http.Request) {
	identity, err := principal(r)
	if err != nil {
		b.finish(w, 401, AuthenticationDenied, "", "", "")
		return
	}
	select {
	case b.active <- struct{}{}:
		defer func() { <-b.active }()
	default:
		b.finish(w, 503, BrokerBusy, identity, "", "")
		return
	}
	if !b.telemetry.healthy() {
		b.reply(w, 503, response{Error: string(TelemetryUnavailable)})
		return
	}
	if r.Method != http.MethodPost || r.URL.Path != "/v1/resolve" ||
		r.URL.RawQuery != "" || r.URL.RawPath != "" ||
		len(r.Header.Values("Content-Type")) != 1 || r.Header.Get("Content-Type") != "application/json" ||
		len(r.TransferEncoding) != 0 || r.ContentLength < 1 || r.ContentLength > maxBody ||
		r.Header.Get("Content-Encoding") != "" || r.Header.Get("Expect") != "" {
		b.finish(w, 400, InvalidRequest, identity, "", "")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	data, err := io.ReadAll(r.Body)
	if err != nil {
		b.finish(w, 400, InvalidRequest, identity, "", "")
		return
	}
	var input request
	if err := strictJSON(data, maxBody, []string{"reference"}, &input); err != nil {
		b.finish(w, 400, InvalidRequest, identity, "", "")
		return
	}
	reference, err := ParseReference(input.Reference)
	if err != nil {
		b.finish(w, 400, InvalidReference, identity, "", "")
		return
	}
	if !b.policy.permits(identity, reference) {
		b.finish(w, 403, PolicyDenied, identity, reference.String(), "")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), operationTimeout)
	defer cancel()
	value, err := b.provider.Resolve(ctx, reference)
	if err != nil {
		category := ProviderUnavailable
		if errors.Is(err, SecretNotFound) {
			category = SecretNotFound
		}
		if errors.Is(err, Canceled) || ctx.Err() != nil {
			category = Canceled
		}
		b.finish(w, 503, category, identity, reference.String(), "")
		return
	}
	if ctx.Err() != nil || len(value) != 64 {
		b.finish(w, 503, ProviderUnavailable, identity, reference.String(), "")
		return
	}
	b.finish(w, 200, "", identity, reference.String(), value)
}

func (b *Broker) finish(w http.ResponseWriter, status int, category Category, identity, reference, value string) {
	event := string(category)
	if category == "" {
		event = "resolved"
	}
	id, err := b.telemetry.emit(event, identity, reference)
	if err != nil {
		b.reply(w, 503, response{Error: string(TelemetryUnavailable)})
		return
	}
	b.reply(w, status, response{Value: value, Error: string(category), RequestID: id})
}

func (b *Broker) reply(w http.ResponseWriter, status int, output response) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Connection", "close")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(output); err != nil {
		if _, telemetryErr := b.telemetry.emit("delivery_failed", "", ""); telemetryErr != nil {
			// The sticky telemetry failure prevents subsequent release.
			return
		}
	}
}
