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

## Authorized Core #4 remediation: F1-F4
1. Replace `go run` child launch with reproducibly built native executables in
   a temporary directory outside the checkout; supervise only returned process
   handles and wait for actual exit before removing assets.
2. Frame broker control commands with monotonic request IDs and return a
   bounded, correlated acknowledgement only after each state transition is
   applied. Reject malformed, unknown, stale, duplicate, missing, and
   post-exit responses without treating pipe write success as acknowledgement.
3. Add real subprocess tests with explicit readiness/control synchronization
   and bounded waits for normal/forced exit, startup timeout/crash, client and
   broker/service termination, provider fault boundaries, concurrent principal
   isolation, restart, and temporary resource cleanup.
4. Capture stdout/stderr for broker, consumer, service, build/startup/failure
   diagnostics, plus supervisor output. Scan every stream for synthetic
   credentials, private-key PEM/material, and secret-bearing bootstrap values.
   Report only safe diagnostics and preserve reference-only config semantics.
5. Inspect key/bootstrap holders and copies, argv/env/file surfaces, inherited
   handles, and termination/cancellation limits. The supervisor retains
   synthetic bootstrap bytes in memory for stream-redaction checks; child
   environments are allow-listed and bootstrap values are not passed in argv or
   environment. Fix only demonstrated, narrow defects; preserve mTLS, provider
   contract, HTTP wire and telemetry schemas.

### F1-F4 contract assertions
1. Every started child is owned, bounded, and reaped by its process handle;
   no executable temp directory is removed before children exit.
2. Control success means the broker applied that exact operation; a pipe write,
   stale or duplicate acknowledgement cannot satisfy a later state transition.
3. Killing one child cannot silently release a credential to another principal
   or trigger plaintext fallback; broker/provider/service failures stay explicit.
4. All captured process and supervisor diagnostics are checked for synthetic
   credential, private-key material, and secret-bearing bootstrap leakage.

### F1-F4 validation
Run the demo and real subprocess lifecycle/fault tests on Windows and Linux CI;
run race tests on Linux, preserve both resolver fuzz targets, vulnerability
scan, formatting, build integrity, and cARL checks. Local cross-compilation is
not a substitute for OS-native process tests. Linux uses a distinct process
group and parent-death signal for each direct child; Windows assigns each
direct child to a kill-on-job-close Job Object and fails startup if assignment
is unavailable. Other operating systems receive no descendant-containment
guarantee. Tests establish only the direct-child cases exercised, not arbitrary
grandchildren, distinct OS users, or protection from same-user/privileged
interference. Do not infer provider preemption beyond the context-aware
synthetic provider.

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
