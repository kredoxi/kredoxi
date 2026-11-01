// Package ipc contains non-production experiments for native local IPC identity.
package ipc

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync/atomic"
	"unicode/utf8"

	"github.com/kredoxi/kredoxi/internal/resolver"
)

const (
	maxRequestBytes = 1024
	testReference   = "kredoxi://v1/demo/example/password"
)

type request struct {
	Reference        string `json:"reference"`
	ClaimedPrincipal string `json:"claimed_principal,omitempty"`
	ClaimedUID       uint64 `json:"claimed_uid,omitempty"`
	ClaimedPID       uint64 `json:"claimed_pid,omitempty"`
}

type reply struct {
	Status string `json:"status"`
	Value  string `json:"value,omitempty"`
}

type experimentBroker struct {
	allowed map[string]map[string]bool
	values  map[string]string
	lookups atomic.Uint32
}

func newExperimentBroker(principal, reference, value string) *experimentBroker {
	return &experimentBroker{
		allowed: map[string]map[string]bool{principal: {reference: true}},
		values:  map[string]string{reference: value},
	}
}

func (b *experimentBroker) resolve(principal string, data []byte) reply {
	input, err := parseRequest(data)
	if err != nil {
		return reply{Status: "invalid_request"}
	}
	ref, err := resolver.ParseReference(input.Reference)
	if err != nil {
		return reply{Status: "invalid_reference"}
	}
	if !b.allowed[principal][ref.String()] {
		return reply{Status: "policy_denied"}
	}
	b.lookups.Add(1)
	value, ok := b.values[ref.String()]
	if !ok {
		return reply{Status: "secret_not_found"}
	}
	return reply{Status: "resolved", Value: value}
}

func randomSyntheticValue() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate synthetic experiment value: %w", err)
	}
	return hex.EncodeToString(raw), nil
}

func syntheticValueDigest(value string) string {
	digest := sha256.Sum256([]byte(value))
	return fmt.Sprintf("%x", digest)
}

func parseRequest(data []byte) (request, error) {
	var zero request
	if len(data) == 0 || len(data) > maxRequestBytes || !utf8.Valid(data) {
		return zero, errors.New("invalid request size or encoding")
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	first, err := decoder.Token()
	if err != nil || first != json.Delim('{') {
		return zero, errors.New("request must be an object")
	}
	allowed := map[string]bool{
		"reference": true, "claimed_principal": true,
		"claimed_uid": true, "claimed_pid": true,
	}
	seen := make(map[string]bool)
	for decoder.More() {
		token, err := decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok || !allowed[key] || seen[key] {
			return zero, errors.New("unknown or duplicate request field")
		}
		seen[key] = true
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			return zero, errors.New("invalid request value")
		}
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim('}') {
		return zero, errors.New("unterminated request object")
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return zero, errors.New("trailing request data")
	}

	decoder = json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&zero); err != nil {
		return request{}, errors.New("invalid request schema")
	}
	if zero.Reference == "" {
		return request{}, errors.New("missing reference")
	}
	return zero, nil
}
