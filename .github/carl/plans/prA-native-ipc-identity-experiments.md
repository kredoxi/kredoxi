# Core PR A: native IPC identity experiments

## Plan metadata
- PR / branch: Core PR A / `goldjg-native-ipc-experiments`
- Status: active; research only; conditional Core PR #5 merge authorized by
  scoped owner-approved contract amendment
- Author: Copilot
- Created: 2026-11-01
- Last updated: 2026-11-01

## Task summary

Build and run isolated native IPC experiments with synthetic assets to test
whether OS account/token identity creates an enforceable local boundary beyond
Kredoxi's current mTLS key-holder model. Core PR A contains experiment code,
tests, and reproducible observations only. Architecture PR B owns the evidence
report and ADR 0002 evaluation. Neither PR accepts ADR 0002 or changes
production architecture.

## Current repository context

Core `main` and the clean starting worktree both point to
`b68ae7a5df757b22cc0091b0b484df0eb8a1ed25`; GitHub's current `main` matched
that commit. There were no open Core PRs or PRs for this task branch. Other
local worktrees are on separate branches and are not modified. Architecture
`main` was `31fe6c414e16e453df7d31c22f217223ceadd25`, with no open PRs.

Core `docs/adr-0001.md` records accepted explicit resolution over loopback
TLS 1.3 mTLS. The source in `internal/resolver` derives the principal from the
verified certificate URI SAN, authorizes exact references before provider
lookup, and distinguishes `policy_denied` from authorized `secret_not_found`.
Core's existing tests cover those semantics and certificate/transport failures.
Architecture ADR 0002 is still Proposed and expressly defers transport choice
pending native experiments and owner approval.

This Windows host runs Go 1.27.3 on Windows/amd64. WSL is installed but has no
Linux distribution; no distinct-account disposable Linux or Windows
environment is available locally. Native Windows tests can run here. Native
Linux results must come from the repository's Linux CI runner; distinct-user
tests remain blocked unless a suitable already-authorized isolated environment
is provided.

Before experiment PR A, cARL v1.0.2's managed trust-boundary artifact was
reconciled in a separate commit. Core PR #4 had added Kredoxi-specific content
to that managed file after its recorded installation; those same controls were
already preserved in the user-owned `.github/carl/kredoxi-controls.md`. The
managed file now matches the verified embedded artifact byte-for-byte, and
official cARL status/effective/trace/harness checks are healthy. The remediation
evidence and hashes are recorded in
`.github/carl/plans/carl-v1.0.2-trust-boundary-reconciliation.md`.

## Previous contract status

The checked-in active contract described the already-merged synthetic MVP and
F1-F4 child supervision, and explicitly deferred native IPC. This task-scoped
contract amends that scope only for isolated research code, tests, docs, and
native CI. Production resolver behavior, protocol, telemetry, and ADR 0001
remain unchanged.

## Contract lifecycle note

Completed PR constraints are historical unless promoted to durable invariants.
This plan does not promote or accept an architecture decision.

## Intentional contract amendments

The current PR contract authorizes native Linux pathname Unix sockets and
Windows named-pipe experiments in `experiments/ipc/`, plus native CI runs. It
does not authorize production IPC, resolver changes, a provider integration,
ADR acceptance, or edits in the Architecture repository.

## Goal

Determine what the native OS evidence actually authorizes, what same-account
and copied-key attackers can still do, and whether requiring both IPC identity
and mTLS provides an independent factor or mainly operational complexity.

## Non-goals

- Production transport or resolver implementation.
- Replacing or augmenting the `/v1/resolve` production/demo path.
- Process or executable attestation, trusted-code claims, or privileged
  attacker testing.
- Creating OS accounts or changing workstation security settings.
- Accepting ADR 0002, changing ADR 0001, or editing/merging Architecture PR B.
- Real secrets, releases, automatic fallback, or any merge outside the scoped
  owner-approved Core PR #5 integration.

## Approved scope

- Linux: pathname AF_UNIX stream endpoint; private parent directory and socket
  modes; safe creation/cleanup; kernel `SO_PEERCRED`; exact-reference mapping;
  endpoint pre-creation/replacement/stale-path and lifecycle checks.
- Windows: named pipe with explicit security descriptor/DACL and remote-client
  rejection; derive client SID from the impersonated token; fail closed on
  impersonation failure; verify `RevertToSelf` and broker-token restoration;
  same-account process, handle, lifecycle, malformed-input and remote-pipe
  cases where the host permits safe execution.
- Shared: synthetic provider/reference policy, count lookups, spoofed fields,
  bounded frames, authorized missing-secret semantics, concurrent clients,
  and safe diagnostics.
- Unchanged mTLS baseline comparison, including separate-process use of a
  copied synthetic key only when safely passed through an in-memory pipe.
- Experimental README, native CI coverage, and scoped governance contract/plan.

## Forbidden scope

Do not write production paths under `internal/`, `cmd/`, or `examples/`; change
protocol/telemetry; change ADR files or Architecture repository; create
accounts; elevate privileges; weaken host controls; install drivers; use real
credentials; claim same-user, executable-integrity, or administrator/root
protection; or perform destructive tests.

## Trust boundaries

Untrusted client bytes are parsed with hard bounds. Linux peer UID/GID/PID comes
from the accepted kernel socket, not request fields; Windows SID comes from the
OS client token while impersonating the pipe client. Both are only OS account
or token evidence. They do not prove executable identity, integrity, or benign
behavior. Authorization remains exact-principal plus exact-reference before
provider lookup. Synthetic credentials/keys stay in memory or bounded pipes and
never in committed artifacts or diagnostic output.

## Invariants to preserve

- mTLS-only production behavior remains byte-for-byte unchanged.
- Default deny, no wildcards, no identity inferred from request fields.
- Unauthorized references return `policy_denied` and produce zero provider
  lookups; only authorized missing references return `secret_not_found`.
- No plaintext fallback, real credentials, secret-bearing logs, persistent
  test resources, or unsupported security claims.
- Native evidence is run on native OS runners; cross-compilation is not
  presented as runtime evidence.

## Expected files / directories

- `experiments/ipc/` for isolated experiment source, tests, helpers, and README.
- `.github/workflows/ci.yml` only for native Linux/Windows test execution.
- `.github/carl/current-pr-contract.md` and this task-scoped plan.

## Implementation phases

1. Establish native endpoint safety and identity acquisition on Windows locally
   and Linux CI; keep each experiment independent of production resolver code.
2. Exercise policy order, identity spoofing, same-account process reuse,
   endpoint replacement, malformed/concurrent requests, termination, and
   synthetic material custody/leakage.
3. Exercise DACL, SID impersonation/restoration, remote access, and handles on
   Windows; record unavailable distinct-account cases without simulation.
4. Compare copied-key mTLS use against native identity results and capture exact
   OS/runtime/test evidence.
5. Run required checks, record only observed results in the experiment README,
   create Core PR A, and hand Architecture PR B's coordinator the evidence.
6. Merge Core PR #5 only after the controlled gates in the owner-approved
   integration amendment pass; then verify the merged default-branch head and
   its native Linux, native Windows, and governance checks.

## Acceptance criteria

1. Native tests show the identity actually obtained from the OS and reject
   forged request identity fields.
2. Exact-reference policy is enforced before provider lookup, preserving
   `policy_denied` versus authorized `secret_not_found`.
3. A separate process under the same OS account is tested; any successful
   access is reported as an explicit same-account bypass, not a prevention.
4. Endpoint permissions, lifecycle failures, request bounds, secret redaction,
   and Windows impersonation restoration fail closed where exercised.
5. The comparison states what mTLS key possession and OS account/token checks
   establish, what they do not establish, and the residual risk of layering.
6. Each scenario records capability, expected result, observed result, and
   residual risk; distinct-account outcomes are reported only after genuinely
   OS-enforced tests in an authorized environment.

## Contract assertions

1. Peer identity comes only from kernel credentials or the impersonated client
   token; forged PID/account/principal fields never alter it.
2. No unauthorized request can trigger provider lookup; an authorized absent
   reference reaches the provider and maps only to `secret_not_found`.
3. Same-account process and copied-key experiments show whether the caller can
   reuse the relevant identity; no executable-attestation claim is made.
4. Native endpoint setup, impersonation restoration, cancellation, and
   diagnostics fail safely without exposing synthetic keys/credentials.

## Test strategy

| Assertion | Direct evidence |
|---|---|
| 1 | Linux native socket peer credentials and Windows native token SID; clients send deliberately false identity fields; assert OS evidence wins |
| 2 | Counting synthetic provider plus allowed/denied/missing reference tests; assert exact categories and lookup count |
| 3 | Helper process under current account; copied synthetic mTLS certificate/key sent only through a private stdin pipe; record whether access succeeds |
| 4 | Platform-native endpoint mode/DACL, path replacement/stale endpoint, Windows impersonation failure/restoration, remote pipe, handle flags, exit and output-redaction tests |
| Native behavior | Core CI matrix runs tests on `ubuntu-latest` and `windows-latest`; no cross-compile substitute |
| Static hygiene | `go test ./...`, `go build ./...`, `go vet ./...`, `go test -race ./...` where supported, gofmt, `govulncheck`, secret scans, and cARL diagnostics |

Unavailable same-account/distinct-account, privileged, or handle-duplication
cases must be marked blocked with the environment and reason; mocks do not
count as native enforcement evidence.

## Prompt ping-pong budget

One corrective prompt is acceptable. Two corrective prompts mean reset the
session. Three means abandon the session/model and restart with a fresh model
or clearer plan.

## Model fallback strategy

Model availability and capability are not stable invariants. Preserve this
plan's scope, non-goals, assertions, and evidence boundaries if switching.

## Stop conditions

Stop any scenario requiring real credentials, a privileged or persistent
account change, weakening a host security control, writing secrets to disk, or
changing production code/Architecture decisions.

## Context reset requirements

Keep the Core contract active through the controlled Core PR #5 merge and
post-merge default-branch validation, then close or supersede it. Architecture
PR B is separately coordinated and out of scope for this session. Do not merge
it or accept ADR 0002.

## Owner-approved integration amendment

On 2026-11-01, the owner explicitly authorized merging Core PR #5 followed by
Architecture PR #4, provided all required security, governance, and CI gates
pass. This session executes Core PR #5 only. It must not bypass branch
protection, merge with stale checks, auto-merge, edit/merge Architecture PR #4,
accept ADR 0002, or change production architecture. Stop unless the exact PR
head is mergeable and all required checks pass; after merging Core #5, verify
its merged state, resulting `main` SHA, and successful default-branch Linux,
Windows, and governance CI before handing off to the owner.
