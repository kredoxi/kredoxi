# Synthetic MVP execution plan

Status: active; implementation explicitly approved by the user execution brief.

## Goal
Demonstrate a consumer using an ephemeral credential resolved over loopback mTLS,
without that credential in its original configuration, across independently
executing broker, consumer, and synthetic service processes.

## Affected files
`internal/resolver/`, `internal/synthetic/`, `cmd/`, `examples/`, `README.md`,
`docs/`, `ROADMAP.md`, and active user-owned cARL state.

## Step-by-step changes
1. Hydrate cARL; record active contract and focused profile retaining core controls.
2. Preserve strict v1 references and JSON, immutable pinned policy, synthetic
   provider, TLS 1.3 authenticated broker/client, and versioned telemetry.
3. Add independently executable broker, consumer, and synthetic-service commands.
   The demo supervisor passes ephemeral synthetic bootstrap material through
   stdin pipes; it does not persist private keys or credentials.
4. Exercise authorized and unauthorized consumers as separate processes, plus
   provider/broker failure, service challenge verification, restart and cleanup.
5. Test adversarial inputs, certificate identity boundaries, policy integrity,
   concurrency, telemetry failure/leakage and resource bounds.
6. Reconcile documentation/cARL; run checks; open the scoped PR without merging.

## Contract assertions and test strategy
1. Exact canonical references only; malformed/traversal/encoding inputs rejected.
2. Dedicated CA + URI SAN key possession and exact policy precede provider access;
   unauthorised callers cannot cause provider lookup.
3. No secrets, identity claims, raw references or TLS diagnostics in telemetry.
4. Provider, broker and telemetry failures are explicit and never return a value.
5. Concurrent/repeated calls stay isolated and policy remains immutable.

Use standard Go tests, independent-process loopback integration tests, race
detector, go vet, gofmt, demo execution and vulnerability/governance diagnostics.
Do not use live credentials or invasive host tests. OS-native IPC and OS-account
identity are explicitly deferred for a separately reviewed Architecture ADR
and owner approval; process separation must not be reported as OS identity
enforcement.

## Risks
Same-user or privileged key/memory theft and authorized application RCE remain
possible. TLS is not process attestation. No portable transparency, durable
vault, zeroization, signed policy rollback protection or EDR resistance claimed.
The stdin bootstrap pipe is a development harness boundary, not a production
enrollment or identity mechanism. No distinct-OS-user test is performed on this
workstation.

## cARL/docs update expectation
Update memory with actual Kredoxi truth; retain installed core invariants, add
synthetic/privacy boundaries, generate a current map and document exact evidence.
