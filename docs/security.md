# Security evidence and limitations

## Threat tiers

| Tier | Demonstrated boundary | Not protected |
|---|---|---|
| 1: passive configuration/source theft | Consumer config holds only non-secret reference; generated fixture absent from source | Reference metadata; attacker with other runtime authorization |
| 2: unprivileged local compromise | Arbitrary TLS caller cannot resolve without enrolled CA key + exact policy; loopback encrypts response | Same-user private-key/memory theft, caller compromise, connection starvation |
| 3: authorized application compromise | Policy constrains accessible references | Authorized credential exfiltration; test deliberately captures value in consumer callback |
| 4: privileged host compromise | No prevention claim | Root/admin memory reads, binary/policy replacement, hooks, termination, audit deletion |

Assets are credentials, private keys, references, policy, binaries and telemetry.
The MVP has no vault master key or cloud authorization. Malicious dependencies
and compromised coding/developer tools can alter source/binaries; governance,
review and scanning reduce risk but are not runtime integrity enforcement.

## Reproducible evidence

`go run ./cmd/demo` checks service challenge success, authenticated policy denial,
unavailable provider and broker shutdown. Tests cover strict malformed/traversal/
Unicode/encoded references, JSON framing/type/duplicate/case/unknown-field abuse,
foreign CA, absent certificate, URI claim mismatch and TLS downgrade, policy
pin tampering/immutability, absent secret, provider-diagnostic redaction,
sticky audit/short-write failure, canceled calls, repeated application requests, client
endpoint restrictions, concurrent authorized/denied clients, request-ID uniqueness,
reference-only config and deliberate authorized-app extraction. Additional tests
reject expired/future/wrong-purpose certificates, missing/multiple identity SANs,
malformed broker responses and redirects. Both parser fuzz targets passed a
5-second run (337,228 reference inputs and 222,560 JSON inputs in this host run).

Application requests can be repeated by authorized holders (intended); TLS
records cannot be replayed as new sessions. TLS 1.3 tickets are disabled server
side; there is no application nonce-based one-shot credential semantics.

Validation on initial Windows amd64 host: Go 1.27.3, standard tests, go vet and
demo passed. Initial Go 1.27.0 govulncheck identified ten reachable standard-
library advisories including GO-2026-6809 (x509) and net/http advisories;
requiring/downloading 1.27.3 cleared the same symbol-level scan. This is a
toolchain fix, not removal/suppression of findings. The runtime has no external
Go modules. Govulncheck v1.1.4 is a separate pinned validation tool.

Read-only security-review agent found no code vulnerabilities in the initial
implementation review. This is review evidence, not a security certification.
Local race attempt failed because cgo/gcc is absent; Linux CI runs it as a
mandatory gate. CI results and final fuzz evidence belong in the PR.

## Remaining attack surfaces

No interception, OS peer/process attestation, key enrollment/persistence,
production secret provider, TTL/rotation/cache, revocation service, policy
signature/antirollback, binary integrity watcher, privileged tamper prevention,
locked memory, reliable zeroization, crash-dump prevention or protected event log.
The simple executable pin detects policy-only edits, not tampering with the
compiled pin and policy together. Events cannot be emitted after SIGKILL or
privileged termination; stopped-broker detection is a client transport failure,
not an independently supervised health monitor.

No secret-bearing filesystem reads/writes means vault symlink/TOCTOU races
are not implemented paths. Embedded source config and build inputs remain
under ordinary repository/toolchain permissions; no secure-file-I/O claim.
Future persistent providers need permissions, symlink/race and rollback testing.
Synthetic credentials/CA keys live for the demo lifetime with leaf certs expiring
after 15 minutes; clock skew affects validity. New resolutions do not re-enroll
or extend expiry.

The audit sink is a trusted synchronous writer. On writer error, no value is
released and failure is sticky; partial output may be invalid JSON. A blocking
writer can hang and an authorized local user can alter stdout/files. Audited
release attempts are not verified delivery; local telemetry is not tamper
resistance or a durable forensic record.

## Safe testing

Use synthetic fixtures only. Do not inspect real environment credentials,
browser stores, OS secret stores or cloud accounts. Do not disable EDR, patch
host security settings, install interception drivers or run privileged exploit
tests on shared hosts. Future invasive tests require disposable isolation.

## Release and licensing

No production release or license added. Before distribution, choose licensing,
CA/enrollment ownership and supported platforms; use protected tagged builds,
reviewed least-privilege signing, checksummed immutable artifacts, SBOM and
attested provenance. Current CI can check artifact hashes but does not sign or
publish them. GitHub secret scanning/Dependabot/private reporting and required
checks are separate controls; don't claim they are enabled from workflow files.
