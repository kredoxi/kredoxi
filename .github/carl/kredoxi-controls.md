# Additive Kredoxi invariants and trust boundaries

These product-specific controls supplement (never override) the managed
`invariants.yml`, `trust-boundaries.md` and effective core packs.

## Invariants
Only synthetic, ephemeral credentials in the MVP; no production credential
store or personal/cloud secret access. No credential or key in repository
fixtures, original consumer config, events, public error messages, or files
written by the demo. Independent commands receive development-only bootstrap
material through bounded stdin pipes. The supervisor holds generated
credentials, private keys, and serialized bootstrap payloads in memory; the
payload bytes remain referenced until diagnostic redaction checks finish.
Child environments are allow-listed, and credentials/keys are not placed in
argv or files.
Authenticate transport before lookup and authorize each exact reference.
Strict whole-string reference grammar; no decoding or filesystem/provider path
joining. Fail closed on audit sink failure. No insecure TLS fallback.
Never describe key possession as executable identity, an audited release attempt
as receipt, or a user-mode process as tamper-resistant to an administrator.

## Runtime boundaries
The development supervisor -> ephemeral stdin bootstrap -> independent broker
and synthetic-service processes. Untrusted broker request bytes -> bounded
strict JSON -> verified certificate identity -> immutable exact policy ->
synthetic provider -> audited release attempt -> TLS response -> explicit
consumer integration.
Client identity claims, process names and PIDs do not participate.
The dedicated development CA is a demo trust root, not an OS enrollment system.
Provider, policy, telemetry writer and their configuration are trusted objects.
The supervisor and every process holding bootstrap material are trusted for
this synthetic demo; process separation does not enforce OS identity.
The demo builds executables in an OS temporary directory, captures child and
supervisor output in memory, and removes that directory only after child exit
is confirmed. Linux direct children use a separate process group and
parent-death signal. Windows direct children use a kill-on-job-close Job
Object; startup fails if job assignment is unavailable. Other operating
systems have no additional containment guarantee. These controls and tests do
not establish arbitrary-descendant cleanup, distinct-user enforcement,
zeroization, or protection from a same-user/privileged actor.

Policy digest is independently compiled and hashes compact JSON, not a document
and its own adjacent checksum. Whitespace differences are harmless. This detects
demo policy edits, not replacement of the executable and pin together.

Local JSON-lines telemetry is privacy-conscious but neither durable nor
tamper-proof. Per-run keyed identifiers hinder dictionary lookup and sacrifice
cross-run correlation. An arbitrary blocking writer/provider is not safely
preemptible; only the synchronous, in-memory provider and stdout are wired by
the demo. Respect deadlines in every future provider.
