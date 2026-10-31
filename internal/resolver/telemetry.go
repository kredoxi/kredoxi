package resolver

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"sync"
	"time"
)

const Version = "0.1.0"

type Event struct {
	SchemaVersion  int    `json:"schema_version"`
	Timestamp      string `json:"timestamp"`
	EventType      string `json:"event_type"`
	RequestID      string `json:"request_id"`
	PrincipalID    string `json:"principal_id,omitempty"`
	ReferenceID    string `json:"reference_id,omitempty"`
	Authentication string `json:"authentication_method"`
	PolicyDecision string `json:"policy_decision"`
	ProviderID     string `json:"provider_id"`
	Status         string `json:"status"`
	ErrorCategory  string `json:"error_category,omitempty"`
	AgentVersion   string `json:"agent_version"`
	Mode           string `json:"mode"`
}

// Telemetry writes only constructed allowlisted events. Identifiers are keyed,
// per-run pseudonyms; a writer failure permanently prevents further resolution.
type Telemetry struct {
	mu     sync.Mutex
	writer io.Writer
	key    [32]byte
	failed bool
}

func NewTelemetry(writer io.Writer) (*Telemetry, error) {
	if writer == nil {
		return nil, TelemetryUnavailable
	}
	telemetry := &Telemetry{writer: writer}
	if _, err := rand.Read(telemetry.key[:]); err != nil {
		return nil, InternalFailure
	}
	return telemetry, nil
}

func (t *Telemetry) pseudonym(value string) (string, error) {
	if value == "" {
		return "", nil
	}
	mac := hmac.New(sha256.New, t.key[:])
	if _, err := mac.Write([]byte(value)); err != nil {
		return "", InternalFailure
	}
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func (t *Telemetry) emit(status, principal, reference string) (string, error) {
	switch status {
	case "started", "stopped", "resolved", "invalid_request", "invalid_reference",
		"authentication_denied", "policy_denied", "secret_not_found",
		"provider_unavailable", "broker_busy", "internal_failure", "canceled",
		"delivery_failed", "transport_failure":
	default:
		return "", InternalFailure
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.failed {
		return "", TelemetryUnavailable
	}
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		t.failed = true
		return "", TelemetryUnavailable
	}
	principalID, err := t.pseudonym(principal)
	if err != nil {
		t.failed = true
		return "", TelemetryUnavailable
	}
	referenceID, err := t.pseudonym(reference)
	if err != nil {
		t.failed = true
		return "", TelemetryUnavailable
	}
	event := Event{
		SchemaVersion: 1, Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		EventType: "resolution", RequestID: hex.EncodeToString(id),
		PrincipalID: principalID, ReferenceID: referenceID,
		Authentication: "mtls-uri-san", PolicyDecision: "not_evaluated",
		ProviderID: "synthetic", Status: status, AgentVersion: Version, Mode: "enforcement",
	}
	switch status {
	case "started", "stopped":
		event.EventType = "broker_health"
	case "resolved":
		event.PolicyDecision = "allow"
	case "policy_denied":
		event.PolicyDecision = "deny"
	}
	if status != "resolved" && status != "started" && status != "stopped" {
		event.ErrorCategory = status
	}
	data, err := json.Marshal(event)
	if err != nil {
		t.failed = true
		return "", TelemetryUnavailable
	}
	data = append(data, '\n')
	written, err := t.writer.Write(data)
	if err != nil || written != len(data) {
		t.failed = true
		return "", TelemetryUnavailable
	}
	return event.RequestID, nil
}

func (t *Telemetry) healthy() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return !t.failed
}
