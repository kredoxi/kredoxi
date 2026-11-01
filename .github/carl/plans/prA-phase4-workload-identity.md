# Core PR A: Phase 4 workload and endpoint trust experiments

## Plan metadata
- Branch: `goldjg-phase4-workload-identity`
- Status: active; isolated research; no merge or ADR acceptance
- Created: 2026-11-01
- Base: Core `main` at `0c465c56a6732265bdad8ec3eba143a11b2a9895`

## Goal

Test what the already-merged Phase 3 IPC mechanisms do and do not establish
about deployment identity, broker authentication, endpoint substitution, and
key custody. Produce evidence for the separately coordinated Architecture
follow-up. Do not change production code or choose an architecture.

## Verified starting point

Core PR #5 (`goldjg-native-ipc-experiments`) is merged. Its current tests cover
Linux pathname sockets/`SO_PEERCRED`, Windows named-pipe DACL and token SID,
same-account processes, request spoofing, exact policy-before-provider,
endpoint pre-creation, same-account Linux endpoint substitution, existing
Linux `nobody` cross-UID cases, a copied synthetic mTLS key, and Windows
impersonation restoration/overlapped I/O. The README records native Windows
results and native Linux CI run 41329082490. Windows different-SID and
remote-host denial were not measured. Current branch started clean at the
merged main SHA above.

The local host is Windows/amd64, Go 1.27.3, `CGO_ENABLED=0`, with no WSL Linux
distribution. Do not create users or alter local host settings. Native Linux
evidence must come from an existing authorized disposable runner. Current cARL
v1.0.2 is healthy; the active `go-mvp` profile hydrates the selected core
governance packs plus Go, PowerShell, and CI/CD.

## Non-goals

- Production IPC, transport, resolver, broker, identity, enrollment, policy,
  trust-root, telemetry, or application changes.
- Accepting ADR 0002, modifying ADR 0001, choosing a deployment architecture,
  or editing Architecture PR B.
- Creating users, services, privileged setup, changing workstation/host
  protections, or testing a privileged attacker.
- Real credentials, paid infrastructure, releases, merges, or automatic
  fallback.

## Scope and method

1. Preserve and inspect the Phase 3 native test harness. Add only isolated
   experiments beneath `experiments/ipc/` and update its README with methods,
   commands, observed results, limitations, and cleanup.
2. Test Linux broker endpoint ownership/parent directory boundaries using only
   existing identities. Where an existing disposable Linux runner permits
   `sudo -n -u nobody`, verify that the unrelated UID cannot rename/unlink or
   replace an endpoint protected by the broker-owned directory. Record owner,
   UID/GID, directory and socket modes, mount/parent assumptions, and the
   observed error. Do not provision an identity.
3. Test fake-broker/endpoint impersonation in a separate synthetic client
   process. Record whether it can connect to an attacker-controlled endpoint,
   what request data is exposed, and whether the client validates broker
   identity. Do not place secret values in the request or report.
4. Extend Windows tests only for behavior observable as the existing current
   unprivileged SID: DACL scope, first-instance/pre-created pipe behavior,
   connected-handle reuse, same-account clients, and peer/broker identity
   claims. Do not provision a second SID. Treat different-SID and remote-host
   denial as unmeasured unless an already-authorized disposable environment
   already exists and can be used without privileged setup.
5. Reaffirm exact-reference policy and provider lookup counts, same-account
   process/handle limits, copied mTLS key reuse, and output redaction. Measure
   IPC+mTLS combination only if the experiment actually enforces both; otherwise
   mark it unmeasured.
6. Add a five-candidate comparison (A shared user; B dedicated broker identity
   with shared consumer account; C broker plus workload identities; D dedicated
   identities plus cryptographic key proof; E existing explicit mTLS only).
   Separate directly measured properties from operational hypotheses. Cover
   enrollment, key custody/rotation/revocation, install/update, lifecycle,
   compromise, removal, rollback/recovery, platform support, failure modes,
   and costs without selecting a candidate.
7. Record OS/build, Go version, architecture, exact runtime identity/privilege
   context, source SHA, commands, results, errors, cleanup, and evidence status
   (observed, configured-only, blocked, or not measured).
8. Run only native tests as evidence. Existing CI already has native Linux and
   Windows jobs; do not modify CI unless the new tests are not included. Do not
   add privileged/account-provisioning steps to CI.
9. Run cARL checks and relevant Go tests/static analysis. Open a separate Core
   PR A after validation, leave it open/unmerged, and hand the evidence to the
   coordinator for Architecture PR B.

## Contract assertions

1. Endpoint access and client authentication do not imply broker
   authentication. If a fake endpoint can impersonate a broker, the test
   records what the client observed and does not claim endpoint names/ACLs
   authenticate the broker.
2. Cross-identity results use kernel/token evidence from real, distinct
   existing accounts. No caller-supplied values, mocks, or same-token
   substitutions count.
3. A same-account process or inherited/duplicated connected handle is not
   treated as a distinct application identity; no executable attestation is
   claimed.
4. Authorization remains exact-reference/default-deny before provider lookup;
   synthetic values and private keys do not appear in output or diagnostics.
5. The candidate comparison labels empirical evidence versus untested
   assumptions, and makes no production decision or ADR acceptance.

## Test strategy

| Assertion | Direct evidence |
|---|---|
| 1 | Native fake-endpoint test against a separate client process; capture only safe request metadata and verify whether broker identity is validated |
| 2 | Linux native existing-UID filesystem replacement/connect tests; Windows only actual current-token evidence absent a permitted disposable second identity |
| 3 | Native same-account endpoint/process/handle tests and synthetic copied-key mTLS baseline |
| 4 | Counting provider and output redaction checks on both supported native runners |
| 5 | README matrix references test IDs and marks unmeasured deployment operations as assumptions, not results |

Validation includes `go test ./experiments/ipc -count=1 -v`, `go test ./...`,
`go build ./...`, `go vet ./...`, `go test -race ./...` where supported,
formatting, `govulncheck`, safe secret/output scans, and cARL status/effective/
trace/harness checks. Cross-compilation and skipped tests are not native
runtime evidence.

## Expected files

- `experiments/ipc/` source, focused tests, and README.
- `.github/carl/current-pr-contract.md`
- `.github/carl/plans/prA-phase4-workload-identity.md`
- `.github/workflows/ci.yml` only if required for existing native jobs to run
  the added experiments.

No update to memory or product controls is planned unless observed results
change durable architecture assumptions beyond documenting the experiment.

## Risks and residual limits

The current host is not an authorized target for privileged/account-provisioning
experiments. There is no local Linux runtime. A Windows DACL flag and a Linux
test's configured filesystem mode do not prove denial unless an actual
different identity attempts the operation. Tests do not establish process
integrity, same-account protection, privileged resistance, production
enrollment, health, delivery, or arbitrary-provider cancellation. No combined
IPC+mTLS protection claim is allowed without a measured test.

## Stop conditions

Stop any scenario requiring real credentials, account/service creation,
privilege elevation, local machine or network/security changes, paid resources,
or production/Architecture edits. Leave unavailable cases blocked and proceed
only with safe experiments that do not imply success.
