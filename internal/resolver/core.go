// Package resolver implements a development-only, synthetic credential broker.
package resolver

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"sync"
	"unicode/utf8"
)

type Category string

func (c Category) Error() string { return string(c) }

const (
	InvalidReference     Category = "invalid_reference"
	InvalidRequest       Category = "invalid_request"
	InvalidPolicy        Category = "invalid_policy"
	PolicyIntegrity      Category = "policy_integrity"
	AuthenticationDenied Category = "authentication_denied"
	PolicyDenied         Category = "policy_denied"
	SecretNotFound       Category = "secret_not_found"
	ProviderUnavailable  Category = "provider_unavailable"
	BrokerUnavailable    Category = "broker_unavailable"
	BrokerBusy           Category = "broker_busy"
	TelemetryUnavailable Category = "telemetry_unavailable"
	InvalidResponse      Category = "invalid_response"
	InternalFailure      Category = "internal_failure"
	Canceled             Category = "canceled"
)

var referencePattern = regexp.MustCompile(`^kredoxi://v1/[a-z][a-z0-9-]{0,31}/[a-z][a-z0-9-]{0,31}/[a-z][a-z0-9-]{0,31}$`)
var principalPattern = regexp.MustCompile(`^urn:kredoxi:principal:[a-z][a-z0-9-]{0,31}$`)

type Reference struct{ value string }

func ParseReference(value string) (Reference, error) {
	if !referencePattern.MatchString(value) {
		return Reference{}, InvalidReference
	}
	return Reference{value: value}, nil
}

func (r Reference) String() string { return r.value }

// strictJSON validates duplicate keys, exact top-level spelling and bounded depth
// before Go's struct decoder (which otherwise accepts duplicate/case-folded keys).
func strictJSON(data []byte, maximum int, keys []string, output any) error {
	if len(data) == 0 || len(data) > maximum || !utf8.Valid(data) {
		return InvalidRequest
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := inspectJSON(decoder, 0, keys); err != nil {
		return InvalidRequest
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return InvalidRequest
	}
	decoder = json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return InvalidRequest
	}
	return nil
}

func inspectJSON(decoder *json.Decoder, depth int, topKeys []string) error {
	if depth > 8 {
		return InvalidRequest
	}
	token, err := decoder.Token()
	if err != nil {
		return InvalidRequest
	}
	delimiter, container := token.(json.Delim)
	if !container {
		if depth == 0 {
			return InvalidRequest
		}
		return nil
	}
	if depth == 0 && delimiter != '{' {
		return InvalidRequest
	}
	switch delimiter {
	case '{':
		seen := make(map[string]bool)
		for decoder.More() {
			token, err = decoder.Token()
			key, ok := token.(string)
			if err != nil || !ok || seen[key] {
				return InvalidRequest
			}
			seen[key] = true
			if depth == 0 {
				allowed := false
				for _, candidate := range topKeys {
					allowed = allowed || key == candidate
				}
				if !allowed {
					return InvalidRequest
				}
			}
			if err = inspectJSON(decoder, depth+1, nil); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err = inspectJSON(decoder, depth+1, nil); err != nil {
				return err
			}
		}
	default:
		return InvalidRequest
	}
	end, err := decoder.Token()
	if err != nil || (delimiter == '{' && end != json.Delim('}')) ||
		(delimiter == '[' && end != json.Delim(']')) {
		return InvalidRequest
	}
	return nil
}

type policyDocument struct {
	Version int                 `json:"version"`
	Allow   map[string][]string `json:"allow"`
}

// Policy has no mutation/reload API. The trusted digest must come from outside
// the untrusted policy document; pinning both in the same file proves nothing.
type Policy struct{ rules map[string]map[string]bool }

func NewPolicy(data []byte, expected [32]byte) (*Policy, error) {
	var document policyDocument
	if err := strictJSON(data, 16384, []string{"version", "allow"}, &document); err != nil {
		return nil, InvalidPolicy
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, data); err != nil {
		return nil, InvalidPolicy
	}
	digest := sha256.Sum256(compact.Bytes())
	if subtle.ConstantTimeCompare(digest[:], expected[:]) != 1 {
		return nil, PolicyIntegrity
	}
	if document.Version != 1 || document.Allow == nil || len(document.Allow) > 32 {
		return nil, InvalidPolicy
	}
	policy := &Policy{rules: make(map[string]map[string]bool)}
	for principal, references := range document.Allow {
		if !principalPattern.MatchString(principal) || len(references) > 64 {
			return nil, InvalidPolicy
		}
		rules := make(map[string]bool)
		for _, text := range references {
			ref, err := ParseReference(text)
			if err != nil || rules[ref.String()] {
				return nil, InvalidPolicy
			}
			rules[ref.String()] = true
		}
		policy.rules[principal] = rules
	}
	return policy, nil
}

func (p *Policy) permits(principal string, reference Reference) bool {
	return p.rules[principal][reference.String()]
}

// Provider implementations must respect context deadlines and return bounded
// errors. The MVP wires only SyntheticProvider, not production secret stores.
type Provider interface {
	Resolve(context.Context, Reference) (string, error)
}

type SyntheticProvider struct {
	mu        sync.RWMutex
	values    map[string]string
	available bool
}

func NewSyntheticProvider(references []string) (*SyntheticProvider, error) {
	provider := &SyntheticProvider{values: make(map[string]string), available: true}
	if len(references) > 64 {
		return nil, InvalidReference
	}
	for _, text := range references {
		ref, err := ParseReference(text)
		if err != nil {
			return nil, err
		}
		if _, exists := provider.values[ref.String()]; exists {
			return nil, InvalidReference
		}
		value := make([]byte, 32)
		if _, err := rand.Read(value); err != nil {
			return nil, InternalFailure
		}
		provider.values[ref.String()] = hex.EncodeToString(value)
	}
	return provider, nil
}

func (p *SyntheticProvider) SetAvailable(available bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.available = available
}

func (p *SyntheticProvider) Resolve(ctx context.Context, reference Reference) (string, error) {
	if ctx.Err() != nil {
		return "", Canceled
	}
	if _, err := ParseReference(reference.String()); err != nil {
		return "", err
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	if !p.available {
		return "", ProviderUnavailable
	}
	value, ok := p.values[reference.String()]
	if !ok {
		return "", SecretNotFound
	}
	return value, nil
}
