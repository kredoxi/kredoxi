# Current PR Contract

## Goal
Run reproducible, synthetic-only Linux pathname Unix-domain socket and Windows
named-pipe experiments to measure whether OS account/token authorization adds
a meaningful local boundary beyond Kredoxi's current mTLS key-holder model.
Use the evidence to inform, but not decide, Architecture ADR 0002.

## Contract status
active

## Non-goals
Production transport, resolver/broker changes, ADR acceptance, production
architecture selection, real credentials, persistent account creation,
workstation security-setting changes, privileged exploitation, OS interception,
process/executable attestation, anti-tamper, release, merge, or Architecture
repository edits.

## Carry-forward rules
Preserve every installed core invariant. Synthetic-only fixtures and honest
security claims are durable requirements.

## Approved scope
An isolated Go standard-library experiment under `experiments/ipc/`, its source
and tests, a reproducible README with measured results and residual risks, and
the minimum CI wiring needed to run native tests on actual Linux and Windows
runners. Update this contract and the task-scoped plan. Create and push Core PR
A after validation; leave it open and unmerged.

Before PR A, a separate governance-reconciliation commit is also authorized:
restore `.github/carl/trust-boundaries.md` byte-for-byte to the official cARL
v1.0.2 embedded artifact after preserving its Kredoxi-specific requirements in
the existing project-owned `.github/carl/kredoxi-controls.md`. Keep this
reconciliation separately reviewable from the IPC experiment commit.

## Intentional amendments
This contract supersedes the completed synthetic-MVP/F1-F4 execution scope for
this branch only. It authorizes non-production OS-native IPC experiments that
the prior Core contract deferred, while preserving the explicit boundary that
no production resolver, broker, provider, or `/v1/resolve` route may change.
Architecture ADR 0001 remains accepted for the MVP. ADR 0002 remains proposed;
only an owner may approve a production architecture or accept that ADR.

## Forbidden scope
No production changes to `internal/resolver`, `internal/synthetic`, `cmd/`,
wire protocol, or telemetry. No IPC routing/provider in production. No personal
or cloud secret access, real credentials, persistent OS users, local security
policy changes, EDR changes, drivers, privileged test setup, releases, merge,
Architecture repo writes, plaintext fallback, or unsupported security claims.
Do not use abstract Linux sockets.

## Architectural constraints
The experiment is independent of the production broker and uses only synthetic
disposable values. Linux uses pathname `AF_UNIX` streams and derives peer
credentials from `SO_PEERCRED`; Windows uses named pipes with an explicit DACL,
client-token SID inspection under impersonation, and checked context restoration.
Both preserve default-deny exact-reference authorization before provider lookup.
Never trust request-supplied identity, PID, name, path, or executable claims.
Use no non-standard Go modules unless a demonstrated native API need is
documented and approved first.

## Security constraints
Bound and validate requests; fail closed on endpoint, identity, authorization,
impersonation, and provider errors. Do not disclose synthetic values, private
keys, raw bootstrap data, or sensitive diagnostics in output. Never treat PID
or process name as executable identity, or account/token identity as code
integrity. Same-account compromise and privileged attackers are not claimed to
be prevented. No automatic mTLS/IPC fallback or bypass.

## Expected evidence
Test forged identity fields, exact-policy denial before provider lookup,
authorized missing-secret semantics, separate same-account client processes,
real distinct-account enforcement only where an already authorized isolated
environment exists, endpoint permissions/pre-creation/replacement/stale path,
broker/client lifecycle, bounded malformed and oversized input, concurrency,
and diagnostic/credential leakage. Windows additionally tests explicit DACL,
token SID derivation, impersonation success/failure, restoration, remote-pipe
denial, and handle inheritance/duplication where safely reproducible. Compare
with unchanged mTLS behavior, including copied synthetic key use. Record each
scenario's capability, expected and observed result, and residual risk.

## Files expected to change
`experiments/ipc/`, `.github/workflows/ci.yml`,
`.github/carl/current-pr-contract.md`,
`.github/carl/trust-boundaries.md`, and task-scoped files under
`.github/carl/plans/`. The reconciliation must not remove or weaken the
project-owned controls in `.github/carl/kredoxi-controls.md`. No other
production or Architecture files are in scope.

## Tests / validation
Run native `go test ./...`, `go build ./...`, `go vet ./...`, formatting,
race tests where supported, `govulncheck`, secret/diagnostic scans, and cARL
status/effective/trace. A real Windows run is possible on this Windows host;
the host has no installed WSL distribution, so Linux native tests require the
repository's actual Linux CI runner. Cross-compilation or mocks do not count as
native Linux evidence. Never create an account or modify host security settings
to manufacture distinct-account results.

## Stop conditions
Any test needing real credentials, administrator/root access, persistent OS
account changes, weakened security controls, or changes to production code
must stop. Stop on unresolved governance drift or unexpected conflicting
external writes.

## Escalation triggers
Any dependency addition, privileged setup, unsupported native API behavior,
production transport change, owner decision, Architecture ADR edit, or
security claim beyond measured evidence.

## Context reset notes
Keep this contract active through Core PR A review, then close or supersede it.
Architecture evidence/ADR evaluation belongs to the separately coordinated
follow-up PR B. Do not merge either PR without explicit owner approval.
