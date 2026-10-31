# Synthetic MVP execution plan

Status: active; implementation explicitly approved by the user execution brief.

## Goal
Demonstrate a consumer using an ephemeral credential resolved over loopback mTLS,
without that credential in its original configuration.

## Affected files
`internal/resolver/`, `internal/synthetic/`, `cmd/demo/`, `examples/`, `go.mod`,
`README.md`, `docs/`, `ROADMAP.md`, `.github/workflows/`, cARL user-owned state.

## Step-by-step changes
1. Hydrate cARL; record active contract and focused profile retaining core controls.
2. Implement strict v1 references and JSON, immutable pinned policy, synthetic
   provider, TLS 1.3 authenticated broker and client, versioned redacted telemetry.
3. Generate an ephemeral private CA and keys in memory; run a consumer challenge
   proof and demonstrate denied caller, unavailable provider and stopped broker.
4. Test adversarial inputs, certificate identity boundaries, policy integrity,
   concurrency, telemetry failure/leakage and resource bounds.
5. Reconcile documentation/cARL; run checks; commit/push/open PR without merging.

## Contract assertions and test strategy
1. Exact canonical references only; malformed/traversal/encoding inputs rejected.
2. Dedicated CA + URI SAN key possession and exact policy precede provider access.
3. No secrets, identity claims, raw references or TLS diagnostics in telemetry.
4. Provider, broker and telemetry failures are explicit and never return a value.
5. Concurrent/repeated calls stay isolated and policy remains immutable.

Use standard Go tests, real loopback integration tests, race detector, go vet,
gofmt, demo execution and vulnerability/governance diagnostics. Do not use live
credentials or invasive host tests.

## Risks
Same-user or privileged key/memory theft and authorized application RCE remain
possible. TLS is not process attestation. No portable transparency, durable
vault, zeroization, signed policy rollback protection or EDR resistance claimed.

## cARL/docs update expectation
Update memory with actual Kredoxi truth; retain installed core invariants, add
synthetic/privacy boundaries, generate a current map and document exact evidence.
