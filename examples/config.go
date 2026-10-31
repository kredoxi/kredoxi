// Package examples embeds non-secret example configuration for the local demo.
package examples

import _ "embed"

const Reference = "kredoxi://v1/demo/example/password"
const Principal = "urn:kredoxi:principal:demo-consumer"

//go:embed consumer.json
var Consumer []byte

//go:embed policy.json
var Policy []byte

// TrustedPolicy is independent of the untrusted embedded policy bytes.
// It is an executable pin, not rollback protection against binary replacement.
const TrustedPolicy = "{\"version\":1,\"allow\":{\"urn:kredoxi:principal:demo-consumer\":[\"kredoxi://v1/demo/example/password\"]}}"
