# Current PR Contract

## Goal
Implement the user-approved, locally runnable synthetic Kredoxi vertical slice
with independently executing broker, consumer, and synthetic service processes.

## Contract status
active

## Non-goals
Production vaults, real credentials, cloud accounts, transparent interception,
process identity attestation, privileged tamper resistance, releases, licensing,
other repositories and organization administration.

## Carry-forward rules
Preserve every installed core invariant. Synthetic-only fixtures and honest
security claims are durable requirements.

## Approved scope
Go standard-library broker, explicit client API, ephemeral synthetic provider,
exact-reference deny-by-default policy, TLS 1.3 mutual authentication,
versioned local telemetry, consumer challenge verification, adversarial tests,
documentation, CI, current cARL integration, commit/push and a PR without merge.
The execution brief explicitly approves governance configuration and CI.

## Intentional amendments
Adopt a Go MVP profile retaining all core controls. Platform/cloud packs remain
installed and selected but inactive unless relevant to a future approved task.
Installed memory describes upstream cARL, not Kredoxi; reconcile repository truth.
Extend the existing synthetic demo across process boundaries without changing
the broker wire protocol or provider-neutral contract. A local demo supervisor
may bootstrap synthetic certificates and values through process stdin pipes;
no private keys or credentials are written to files. OS-native IPC, OS-account
enforcement, and executable identity remain undecided and require a separately
reviewed Architecture ADR and owner approval.

## Forbidden scope
No personal secret-store access, credential harvesting, production secret store,
privileged host modifications, security-control weakening, release or PR merge.

## Architectural constraints
Loopback-only TLS 1.3 between independent broker and consumer processes. The
separate synthetic service verifies a challenge response. URI
`kredoxi://v1/demo/example/password`.
Client certificate URI SAN `urn:kredoxi:principal:demo-consumer`.
Certificate possession is not executable identity. No external Go modules.

## Security constraints
Strict grammar and JSON, no arbitrary provider paths, authenticate before lookup,
exact immutable policy, no credentials in config/events/errors, bounded requests,
explicit unavailable provider/broker/telemetry errors, no caching in the client.
Ephemeral private CA and keys stay in memory in the synthetic demo.

## Files expected to change
`internal/`, `cmd/`, `examples/`, `README.md`, `docs/`, `ROADMAP.md`, and this
active contract/plan as needed. Do not modify managed harness adapters or
unrelated CI/dependency policy.

## Tests / validation
`go test ./...`, race detector where C toolchain exists, `go vet ./...`,
gofmt, `go run ./cmd/demo`, vulnerability scan, cARL status/effective/trace.
Tests must cover parsing, authentication, policy, independent-process success
and denial, failures, leakage, lifecycle and isolation.

## Stop conditions
Real credentials required; unresolved governance drift; unexpected conflicting
external writes; permission denials preventing safe execution.

## Escalation triggers
Production-provider work, process/OS interception, new dependencies, privilege
changes, releases, licensing or unsupported claims.

## Context reset notes
Keep the contract active until the PR is reviewed; do not merge.
