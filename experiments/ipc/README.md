# Native IPC identity experiments

These tests are a non-production experiment. They do not change the production
resolver or transport, and they do not accept Architecture ADR 0002. All
credentials and resolved values are generated synthetically for each test run.

## Reproduce

Run on the native operating system; cross-compilation is not runtime evidence:

```powershell
go test ./experiments/ipc -count=1 -v
```

```sh
go test ./experiments/ipc -count=1 -v
```

The repository CI also runs the experiment verbosely and `go test ./...` on
native Ubuntu and Windows runners. Linux's optional distinct-UID cases use only
the already-existing `nobody` account and skip with a reason when passwordless
`sudo` is unavailable. They do not create or modify accounts. No Windows
second-account or remote-host test is simulated.

## What the experiment measures

The synthetic broker accepts one bounded JSON request, derives its principal
from native peer evidence, then applies exact-reference policy before looking
up a synthetic value. Request-supplied identity fields are deliberately false.
The common tests reject malformed, duplicate, oversized, and trailing data;
unauthorized references cause zero provider lookups, while an authorized
missing reference returns `secret_not_found` after exactly one lookup.

The unchanged production mTLS broker is also exercised with a separate helper
process. Its ephemeral client certificate and private key are passed through a
bounded stdin pipe; the test asserts that output and telemetry do not contain
the key or resolved synthetic value. This demonstrates key reuse by a process
that possesses a copy, not a production transport change.

### Linux pathname Unix socket

The native test derives UID, GID, and PID from `SO_PEERCRED`, checks the socket
owner and `0700` parent / `0600` socket modes, rejects pre-created and stale
paths, and confirms that cleanup does not remove a substituted path. A process
under the same account can rename the pathname and bind a replacement; a
client following that path reaches the replacement endpoint. This is an
observed same-account endpoint-substitution capability, not a protected
endpoint guarantee.

When an already-authorized isolated runner permits `sudo -n -u nobody`, the
cross-UID cases first use a traversable `0711` parent with a `0600` socket to
measure kernel permission denial before broker acceptance, then use a
`0666` socket to reach broker policy and measure exact-UID denial. A separate
case compares this with successful use of a copied synthetic mTLS key by that
other UID. If the account or permission is unavailable, the tests report a
skip rather than substituting a simulated identity.

### Windows named pipe

The test requests an explicit DACL scoped to the broker's current user SID,
first-instance creation, non-inheritable handles, and remote-client rejection.
The same-account helper process resolves successfully, proving that another
process under the authorized SID can reuse that account boundary. Impersonation
failure returns `authentication_denied` without provider access; successful
impersonation observes the client SID and checks that both the thread token and
broker process token are restored. The broker verifies the thread token is
absent on the still-locked OS thread before releasing it. Timed-out overlapped
I/O is canceled and its completion is drained before the operation, event, or
buffer can leave scope. An already-connected handle can be duplicated and used
to finish the request.

The first-instance test rejects a pipe name that is already occupied and
confirms that the name can be reused after closure. The remote-client flag is
verified as configured, but denial from a separate remote Windows host is not
measured here. A second Windows account is not available in this environment,
so denial of a different SID by the DACL is likewise unmeasured.

## Phase 4: endpoint and deployment identity boundaries

The test roles are B (broker/listener), A (client), U (unrelated OS identity),
S (another process under the same OS identity), I (a process that creates a
fake endpoint), and K (a process given a copy of the synthetic mTLS key).
These labels do not imply separate accounts: the ordinary broker/client tests
run under the same OS identity. Linux CI's `nobody` case is a real distinct
existing UID; no test creates an account. A privileged attacker is an analytic
out-of-scope case, not a tested actor.

The fake-endpoint tests start an attacker-controlled Unix socket or named pipe
before the client connects. They verify the OS identity of the connecting
client, inspect the bounded synthetic reference request, and return a
synthetic response selected by I. The client accepts that response because
this experiment has no broker-authentication check. This demonstrates that
endpoint reachability, a random endpoint name, and a server-side DACL do not
authenticate B to A. The request contains a reference and deliberately false
identity claims, not a credential or private key; this does not establish
confidentiality for other client protocols.

Linux additionally uses a broker-owned `0700` temporary directory with a
deliberately broad `0666` socket. On a runner where the pre-existing `nobody`
account is available without prompting, the test verifies the helper's actual
UID and attempts to rename and unlink the socket. A denial is evidence about
that directory and account on that run; it is not evidence about every parent
directory, mount, ACL, container namespace, or deployment service. Those
ancestors and mounts must remain trusted. Windows fake-endpoint and DACL tests
run only under the current unprivileged SID. No separate Windows SID, remote
host, service identity, or privileged endpoint takeover is provisioned or
simulated.

### Phase 4 scenario status

| Scenario | Expected | Observed/status | Residual risk |
|---|---|---|---|
| Linux client connecting to I's fake socket | Client should validate B before accepting a response. | Passed on native Ubuntu 24.04 CI at Phase 4 source SHA `9cae544d85ececd814e2977f0e32741ec1b9b773`. | Experiment client has no broker authentication; do not infer production client behavior. |
| Windows client connecting to I's fake pipe | Client should validate B before accepting a response. | Passed on native Windows/amd64 locally and on the Windows Server 2025 CI runner using the actual current token SID; response was synthetic. | No second SID or remote host was used; DACL does not identify trusted code. |
| Linux U replacing/unlinking B's endpoint | Private broker-owned parent directory should block U even when the socket mode is deliberately broad. | Passed on native Ubuntu 24.04 CI at source SHA `9cae544d85ececd814e2977f0e32741ec1b9b773`; the test ran as the existing `nobody` UID and verified it differed from the broker UID. | Only the tested directory and UID are covered; parents, mount configuration, and privileged actors remain trusted. |
| Windows different-SID pipe access | DACL should deny U. | Blocked: no already-authorized disposable Windows identity environment; not simulated. | Configured DACL is not a measured cross-SID denial. |
| Remote Windows pipe access | Remote client should be denied. | Not measured; the existing test confirms only the configured flag. | Configuration is not observed remote-host denial. |
| Same-account process and endpoint substitution | S should be distinguishable from A, or endpoint replacement prevented. | Existing Linux test shows S can replace the pathname; existing Windows test shows same-SID client access and duplicated-handle reuse. | Neither mechanism attests executable identity or separates same-account code. |
| Client request contents at fake endpoint | No credential/private key should be sent in this IPC request. | The fake servers observe only the bounded synthetic reference and false claims; the private key is not part of this test protocol. | No claim about another protocol or a compromised client. |
| IPC plus mTLS | Both controls should be required before claiming a combined factor. | Not measured; no combined enforcement is implemented. | Layering may add key/lifecycle complexity without limiting same-account compromise. |
| Application health or consumption | A successful write should prove application consumption. | Not measured. | Delivery attempt, write completion, application consumption, and health are distinct events. |

### Deployment candidates (research comparison, not a selection)

| Candidate | Enforced distinction and experiment evidence | Enrollment, custody, and lifecycle | Compromise, recovery, support, and cost |
|---|---|---|---|
| **A. Shared user** | Processes under the shared account have the same OS principal. Same-account endpoint access/substitution and handle reuse are observed in the native experiments. | Simplest install/update/restart/removal and rollback; no separate workload enrollment or key rotation. | A compromised process in that account can act as the other same-account process. Low operational cost; no process-specific boundary. |
| **B. Dedicated broker identity; consumers may share an account** | A broker-owned namespace can deny unrelated U access; the new Linux parent-directory replacement test is pending native CI. Windows cross-SID denial is not measured. Shared consumers still collapse to one OS identity. | Requires service identity installation, ACL ownership, restart/recovery and removal procedures; identity/ACL migration must be coordinated with updates and rollback. No service provisioning was tested. | Broker identity compromise exposes broker authority; consumer-account compromise affects all consumers in that account. Additional deployment support and account administration; platform behavior must be validated. |
| **C. Broker plus workload identities** | Could authorize A separately from other workloads only if the OS/platform supplies a trustworthy workload identity at the resource boundary. No workload-identity enrollment or validation was implemented. | Requires per-workload enrollment, mapping, rotation/revocation, update/restart coordination, deprovisioning and recovery. | Per-workload compromise can be scoped if identity and policy are correctly bound; availability depends on the identity source. Higher integration/support cost and platform-specific behavior; currently unmeasured. |
| **D. Dedicated identities plus cryptographic key proof** | Potentially combines account isolation with proof of key possession. The copied-key mTLS experiment demonstrates key reuse by any process that receives the synthetic key; combined IPC+mTLS enforcement is not measured. | Adds key generation, protected custody, enrollment, rotation/revocation, backup/recovery, update and removal paths on top of dedicated identity management. | A copied/exportable key or compromise of the authorized process can erase the intended separation. Highest operational complexity; hardware-backed/non-exportable custody and cross-platform behavior are untested. |
| **E. Existing explicit mTLS only** | The existing mTLS implementation authenticates a certificate principal and applies exact-reference policy; synthetic copied-key tests show possession permits use by a separate process. It does not assert local account or executable identity. | Existing ephemeral demo trust material is managed in memory for experiments. Production enrollment, key custody, rotation, revocation, and recovery remain open design questions. | Key compromise enables use as that certificate principal; no local account isolation is claimed. Lowest change to the current mTLS design; measured behavior is limited to the existing synthetic demo. |

Only the named test observations are empirical. Account enrollment, Windows
cross-SID/service behavior, workload identity, non-exportable key custody,
rotation, revocation, install/update, failure recovery, rollback, and cost are
design considerations and were not operationally measured. No candidate is
recommended by this comparison.

### Phase 4 native run record

The tested source was Core PR #6 head
`9cae544d85ececd814e2977f0e32741ec1b9b773`; GitHub Actions run
[41341406034](https://github.com/kredoxi/kredoxi/actions/runs/41341406034)
passed governance, native Ubuntu, and native Windows jobs. The Ubuntu runner
was `ubuntu-24.04` (image `20261025.353.1`), Go `1.27.3 linux/amd64`. The
Linux experiment command was `go test ./experiments/ipc -count=1 -v`; the
endpoint rename/unlink, fake broker, distinct-UID policy-denial, and copied-key
tests all passed without skips. The existing `nobody` account was used, not
created, and the test checked its actual UID differed from the endpoint owner.
The configured `0700` parent blocked both rename and unlink even though the
socket was deliberately `0666`. Its parent ancestry and mount settings were
not audited.

The Windows CI runner was Microsoft Windows Server 2025, image
`windows-2025-vs2026`, Go `1.27.3 windows/amd64`; the additional local run was
Windows NT `10.0.26300.0`, also Go `1.27.3 windows/amd64`. The fake-pipe server
read the actual client token SID and verified it matched the SID granted by
the test DACL; the SID literal is intentionally not copied into this report.
`TestWindowsClientAcceptsSyntheticFakeBroker` passed on both native Windows
environments. The remote-host denial case remained explicitly skipped because
no separate authorized Windows host was available. No Windows second account
was created or simulated.

The CI job also ran `go build ./...`, `go test ./...`, `go vet ./...`,
Linux `go test -race ./...`, both configured five-second resolver fuzz runs,
formatting, `govulncheck`, and repeat-build integrity; all passed. Temporary
socket directories, helper binaries, and pipe handles were cleaned by the
tests. No persistent account, service, or credential was created.

### Custody and lifecycle limits

The copied-key baseline sends bounded synthetic material through the helper's
stdin; the helper environment is allow-listed, and the tests check captured
stdout/stderr and telemetry for key/value disclosure. No key is placed in a
test fixture, command-line argument, or file. The fake-endpoint tests send no
key at all. Windows checks that the tested pipe handles are not inheritable,
and separately demonstrates that a duplicated connected handle retains
access. It does not test arbitrary handle inheritance or process-memory
extraction. Linux paths are temporary test paths; no full mount/ancestor trust
audit is performed. Windows overlapped timeouts are canceled and drained;
request bounds and disconnect behavior are tested on both transports, but an
arbitrary blocking provider cannot be preempted. No zeroization, production
service recovery, policy-digest custody, or health/consumption guarantee is
claimed.

## Observations from this run

Local environment: Windows NT 10.0.26300.0, Go 1.27.3, `windows/amd64`.
Native experiment tests and the full repository test suite passed;
`go build ./...`, `go vet ./...`, and `govulncheck` passed, with no known
vulnerabilities reported. The native Windows remote-host denial and
different-account cases were not run because no separate authorized Windows
host/account was available.

Native CI evidence: [GitHub Actions run 41329082490](https://github.com/kredoxi/kredoxi/actions/runs/41329082490),
using Go 1.27.3 on `ubuntu-latest` and `windows-latest`, passed both OS jobs and
the governance job. On Linux, every experiment test passed, including the
existing-`nobody` cross-UID socket-permission denial, `SO_PEERCRED` policy
denial, and copied-key mTLS use; none of those tests skipped. Linux
`go test -race ./...` and both five-second resolver fuzz runs also passed. On
Windows, the native experiment tests passed and the remote-host denial test
explicitly skipped because no separate authorized Windows host was available.
A Windows race test was not run locally: this host has `CGO_ENABLED=0` and no
GCC, and `go test -race` requires cgo here.

## Scenario-level results

“Pending native Linux CI” means the source compiled for Linux on the Windows
host, but that is not runtime evidence. Windows outcomes below are from native
Windows execution unless marked blocked. The separate-UID Linux cases may also
skip on CI if the runner does not permit passwordless switching to its existing
`nobody` account.

| Scenario | Expected | Observed | Residual risk |
|---|---|---|---|
| Common malformed/duplicate/oversized request and policy order | Reject malformed input; deny unauthorized references before provider lookup; authorized missing reference yields `secret_not_found`. | Passed on native Windows and Linux CI run 41329082490. | Does not validate the production wire protocol; experiment only. |
| Separate same-account process, Linux pathname socket | Kernel peer UID/GID/PID identify the helper; exact policy resolves. | Passed on native Linux CI run 41329082490. | Same-UID code can connect; peer credentials do not attest executable integrity. |
| Socket directory/endpoint ownership and modes | Parent is `0700`, socket is `0600`, and socket owner is the creating UID. | Passed on native Linux CI run 41329082490. | These are experiment setup values, not a deployment guarantee. |
| Linux peer-field spoofing | False UID/PID/principal fields do not change kernel identity or policy. | Passed on native Linux CI run 41329082490. | OS account identity does not identify trusted code. |
| Linux pre-created/stale endpoint | Startup refuses existing paths without overwriting or unlinking them. | Passed on native Linux CI run 41329082490. | Same-account actors can still alter accessible parent directories. |
| Linux same-account endpoint substitution | A same-account actor can replace the pathname endpoint and receive clients that follow it. | Passed on native Linux CI run 41329082490. | Pathname lookup is not protected from a process with directory write access. |
| Linux socket permission across distinct UIDs | With a traversable `0711` parent and `0600` socket, the other UID cannot connect. | Passed on native Linux CI run 41329082490 using existing `nobody`; no skip. | File modes protect the endpoint only while its directory and owner remain trusted. |
| Linux exact-UID policy across distinct UIDs | With `0666` socket access, real `SO_PEERCRED` UID is denied before lookup. | Passed on native Linux CI run 41329082490 using existing `nobody`; no skip. | This proves account policy in the tested setup, not executable integrity. |
| Linux copied mTLS key under distinct UID | A process given the copied synthetic key can use the mTLS baseline independently of its OS UID. | Passed on native Linux CI run 41329082490 using existing `nobody`; no skip. | Key custody, not OS UID, controls mTLS key reuse. |
| Linux concurrent authorized and denied requests | All results match exact policy; only authorized requests reach the provider. | Passed on native Linux CI run 41329082490. | Does not validate arbitrary provider cancellation or preemption. |
| Linux client disconnect | An incomplete request is rejected without provider lookup and does not stop the broker. | Passed on native Linux CI run 41329082490. | Abrupt disconnect behavior is limited to this framed test protocol. |
| Windows named pipe DACL and same-account process | Explicit current-SID DACL permits a same-SID helper; OS token SID is observed despite false fields. | Passed on native Windows. Different-SID denial was not measured. | DACL configuration is not executable identity; another process under the allowed SID can connect. |
| Windows impersonation failure | Invalid client handle fails closed with no provider lookup and no broker-token change. | Passed on native Windows. | A real OS-level impersonation failure mode beyond the invalid-handle case was not induced. |
| Windows successful impersonation and restoration | Observe the client SID, then restore the thread and process to broker context. | Passed on native Windows. | This checks request-scoped token use, not code trust. |
| Windows restoration verification ordering | Verify the broker thread has no client token before unlocking the OS thread; do not unlock if verification fails. | Passed on native Windows, including focused ordering regression test. | Does not exercise a real `RevertToSelf` failure; that path remains fail-stop. |
| Windows overlapped timeout and cancellation | Cancel timed-out pipe I/O and wait for terminal completion before releasing OVERLAPPED/event/buffer resources. | Passed on native Windows, including a real pending-read cancellation test repeated four times. | If cancellation cannot complete, the operation waits rather than risking resource release while outstanding. |
| Windows first instance and name reuse | Reject an occupied pipe name; allow name reuse after closure. | Passed on native Windows. | Namespace reuse after broker shutdown remains possible by design. |
| Windows duplicated connected handle | A duplicated handle retains access to the already-connected pipe. | Passed on native Windows. | A process that obtains a connected handle can reuse that capability. |
| Windows client disconnect and broker exit | An incomplete frame is rejected without lookup and the one-request test server finishes; explicit shutdown without a client exits. | Passed on native Windows. | Tests bounded local lifecycle only; no persistent service recovery behavior is claimed. |
| Windows concurrent authorized and denied clients | Six concurrent requests produce correct exact-policy results; only three authorized requests reach the provider. | Passed on native Windows. | Does not test arbitrary provider blocking or preemption. |
| Windows remote-client rejection | A remote client is denied. | Not measured: no separate authorized Windows host was available. The test only verifies that `PIPE_REJECT_REMOTE_CLIENTS` is configured. | Configuration intent is not an observed remote-host denial. |
| Separate process using copied synthetic mTLS key | A process possessing the key resolves an authorized reference. | Passed on native Windows. Key and value were absent from captured output and telemetry. | Any process that obtains the private key can reuse it; mTLS does not prove local account or executable identity. |
| IPC plus mTLS | Do not claim an independent factor without testing an explicit combined design. | No combined authentication requirement was implemented or measured. | Combining mechanisms may add lifecycle and custody complexity without stopping compromised same-account code. |

## Interpretation

| Mechanism | What the observed evidence establishes | What it does not establish |
|---|---|---|
| mTLS client certificate | Possession of an authorized private key and successful certificate validation. | Local account identity, executable identity, or benign code. |
| Linux `SO_PEERCRED` | The connected process's kernel-reported UID/GID/PID at connection time. | Executable integrity or protection from same-UID code. |
| Windows named pipe token | The impersonated client's current SID for the request, under the configured pipe security. | Executable integrity or protection from another process under the same SID. |
| IPC plus mTLS | No independent-factor conclusion; the combination was not implemented or measured. | That two mechanisms necessarily stop an authorized account compromise. |

PID/check-use races were not separately injected: the experiments do not use
PID as an authorization input after obtaining per-connection OS evidence, and
neither peer credentials nor a process ID is treated as executable attestation.

Neither account identity nor certificate possession proves that code is
trustworthy. A privileged attacker, arbitrary code execution as the authorized
user, persistence, complete zeroization, and preemption of an arbitrary
blocking provider are outside the evidence and are not claimed to be stopped.
IPC does not replace exact-reference authorization. No automatic mTLS/IPC
fallback is implemented.
