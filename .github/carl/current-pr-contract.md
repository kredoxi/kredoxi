# Current PR Contract

## Goal
Advance the merged native IPC mechanism experiments into experimentally
validated deployment-boundary research: broker endpoint authentication,
cross-identity endpoint protection, same-account and copied-key limits, and
deployment identity/key-custody trade-offs. Use synthetic values only. Inform a
separate Architecture follow-up without selecting a production transport or
accepting ADR 0002.

## Contract status
active

## Non-goals
Production mTLS, resolver, endpoint, broker, telemetry, trust-root, or policy
changes; production IPC; ADR 0002 acceptance; production architecture selection;
real credentials; persistent accounts or services; workstation security,
account, or network changes; privileged attacker testing; paid infrastructure;
releases; automatic merges; Architecture repository edits.

## Approved scope
Extend the isolated Go experiments and documentation under `experiments/ipc/`
with bounded, reproducible tests that use existing identities and synthetic
fixtures. Measure endpoint replacement/pre-creation, broker impersonation,
consumer-to-broker authentication, same-account access, existing Linux
cross-UID boundary behavior, exact-reference policy ordering, and synthetic
mTLS key reuse. Run native Windows checks only within the current unprivileged
identity; run Linux distinct-UID checks only through an already-existing
account on an authorized disposable runner. Do not provision accounts or
services. Update this contract and the task-scoped Phase 4 plan. Create a
separate Core PR A after validation and leave it open and unmerged.

Update CI only if the existing native Linux/Windows jobs do not exercise the
new tests. Do not add privileged account provisioning to CI.

## Intentional amendments
This contract supersedes the completed native-IPC/PR #5 task contract for new
work on this branch. Core PR #5 is already merged at `0c465c56a6732265bdad8ec3eba143a11b2a9895`;
its conditional merge authorization has expired and does not authorize merging
this PR A. This phase is research-only; its report may inform Architecture PR B
but does not decide the architecture.

## Forbidden scope
No production changes to `internal/`, `cmd/`, `examples/`, protocol, or
telemetry; no edits to Architecture; no user or service-account creation,
privilege elevation, machine/network/security setting changes, drivers,
real/paid infrastructure, credentials, or privileged tests. Do not test on
the owner's workstation or Gaia when a scenario needs account provisioning or
privileged access. No automatic fallback, plaintext transport, merge, or
unsupported security claims. A configured control is not evidence that the
control blocked an attacker.

## Architectural and evidence constraints
The experiment is independent of the production broker. Preserve exact,
default-deny reference authorization before provider lookup and count provider
lookups. Obtain caller evidence only from the OS; request fields, endpoint
names, PIDs, process names, paths, and executable hashes are not caller or code
identity. Separate endpoint access, client identity, broker authentication,
key possession, authorization, delivery attempt, write completion, application
consumption, and health evidence. Report prevention, detection, limitation,
and unmeasured scenarios separately. Random endpoint names and endpoint ACLs
alone are not broker authentication. Do not claim that account identity proves
executable integrity or protects against same-account or privileged code.

## Security constraints
Use only synthetic values and ephemeral test assets; never write private key
material or synthetic values into fixtures, output, or telemetry. Keep
requests bounded and fail closed. Do not create or alter OS accounts, services,
security controls, or network exposure. Do not imitate a distinct identity
with request fields, a mock, or the same token. Do not make production trust
root, enrollment, rotation, or policy changes. Preserve existing tests and CI
security boundaries; no privileged setup for untrusted pull-request code.

## Expected evidence
Record actual OS, build, Go version, architecture, identity/privilege context,
source SHA, exact command, expected and observed result, errors, cleanup, and
whether each claim is observed, configured-only, blocked, or not tested.
Include endpoint pre-creation/replacement and fake-broker behavior; Linux
existing-UID access/replacement outcomes; Windows actual token/DACL outcomes
available without account provisioning; same-account process, handle, and
copied-key limits; exact-reference/provider lookup behavior; credential
exposure; and an evidence-qualified comparison of deployment candidates A-E.
Do not claim cross-platform behavior based on compilation, mocks, or skips.

## Files expected to change
`experiments/ipc/`, `.github/carl/current-pr-contract.md`, and
`.github/carl/plans/prA-phase4-workload-identity.md`. Change
`.github/workflows/ci.yml` only if additional native test invocation is
necessary. No production or Architecture files are in scope.

## Tests / validation
Run focused native `go test ./experiments/ipc -count=1 -v`, then relevant
`go test ./...`, `go build ./...`, `go vet ./...`, `go test -race ./...` where
supported, formatting, `govulncheck`, and secret/diagnostic scans. Use native
Linux CI for Linux behavior; local cross-compilation is not runtime evidence.
Run cARL status, effective, trace, and harness checks. Leave unavailability
explicit; do not simulate missing account or platform evidence.

## Stop conditions
Stop if a scenario requires real credentials, account/service creation,
privilege elevation, workstation or Gaia changes, weakening host protections,
network exposure, paid infrastructure, or production/Architecture changes.
Stop on conflicting governance state or unexpected concurrent work.

## Escalation triggers
Any dependency, privileged test setup, CI account provisioning, production
trust-root/authentication change, production transport, Architecture edit,
ADR acceptance, or claim beyond observed evidence.

## Contract assertions
1. A local endpoint or endpoint ACL is not reported as broker authentication
   unless client-observed broker identity is actually validated.
2. Cross-account results use kernel/token evidence from genuinely distinct
   existing identities; no simulated identity or account provisioning.
3. Same-account process, connected-handle, and copied-key capabilities are
   reported as observed limitations, not executable identity.
4. Exact-reference denial occurs before provider lookup, and secrets remain
   absent from test output and diagnostics.
5. Candidate comparison separates measured facts from untested deployment
   assumptions and does not recommend/accept a production ADR.

## Context reset
Keep this contract active through Core PR A review. Leave PR A open and
unmerged. Architecture PR B is separately coordinated and out of scope.
ADR 0002 remains Proposed.
