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
broker process token are restored. An already-connected handle can be
duplicated and used to finish the request.

The first-instance test rejects a pipe name that is already occupied and
confirms that the name can be reused after closure. The remote-client flag is
verified as configured, but denial from a separate remote Windows host is not
measured here. A second Windows account is not available in this environment,
so denial of a different SID by the DACL is likewise unmeasured.

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
