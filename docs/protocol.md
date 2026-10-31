# MVP protocol and configuration contracts

## Reference v1

```
kredoxi://v1/<provider>/<namespace>/<name>
segment = [a-z][a-z0-9-]{0,31}
```

Exactly three nonempty 1–32-character ASCII segments; a lowercase letter starts
each. A trailing hyphen is permitted. The complete string must match. No percent
encoding, Unicode, userinfo, ports, queries, fragments, extra slashes, whitespace
or path traversal. No decoder or path joiner interprets references.
`v1` is a grammar version; changed meaning requires a new version.
Names may reveal metadata, so telemetry never emits raw names.

## Broker API

Loopback IPv4 only, ephemeral port, HTTPS TLS 1.3 only. Dedicated CA verifies
server IP SAN `127.0.0.1` and client certificate trust/expiry/client-auth purpose.
The client certificate must have exactly one canonical URI SAN:
`urn:kredoxi:principal:<segment>`. TLS proof of private-key possession is
authentication, then the broker independently evaluates authorization.

`POST /v1/resolve`, `Content-Type: application/json`, exact JSON object:

```json
{"reference":"kredoxi://v1/demo/example/password"}
```

No client identity field/header is trusted. A valid but unenrolled policy
principal receives denial. Duplicate keys (including nested policy keys),
unknown/case-folded fields, invalid UTF-8, additional JSON values and malformed
types are rejected. Go null-to-empty string decoding is caught by grammar checks.
Request object fields are case-sensitive; JSON escape spelling is decoded
normally and the resulting reference must satisfy the grammar.

Success response:

```json
{"value":"<64-character synthetic hex credential>","request_id":"<32-character hex ID>"}
```

Errors contain `error` and `request_id`, never `value`. Audit failure has empty
request ID since no event could be committed. `Cache-Control: no-store`,
connection closure, no HTTP redirects and no environment proxy support.
Endpoint path versions the request/response contract; there is no separate
`schema_version` request field in this initial API.

| HTTP | Public category | Meaning |
|---|---|---|
| 200 | no error | Authorized synthetic value, pre-release event recorded |
| 400 | invalid_request / invalid_reference | Invalid framing, JSON or grammar |
| 401 | authentication_denied | TLS-verified cert has invalid/ambiguous principal SAN |
| 403 | policy_denied | Authenticated principal lacks exact reference permission |
| 503 | secret_not_found | Authorized reference absent from provider |
| 503 | provider_unavailable / canceled | Provider failed or operation canceled |
| 503 | broker_busy | Active-resolution limit reached |
| 503 | telemetry_unavailable | Audit writer failed; release denied until restart |

TLS failures happen before HTTP and return `broker_unavailable` to the explicit
client, just as unavailable/replaced broker does; no lookup or identity-detail
oracle is exposed. A transport-failure event excludes TLS diagnostic text.
The client uses `invalid_response` for malformed responses and `canceled` for
its canceled context. No automatic retry is performed.

## Policy and provider

```json
{"version":1,"allow":{"urn:kredoxi:principal:demo-consumer":["kredoxi://v1/demo/example/password"]}}
```

No wildcard, default allow or caller-asserted process identity. At most 32
principals and 64 references per principal; duplicate entries rejected. Policy
is immutable with no reload API. `NewPolicy` checks SHA-256 over `json.Compact`
bytes against an independently trusted digest. Whitespace/line endings do not
change the pin; modifying executable and pin together defeats it.

```go
type Provider interface {
    Resolve(context.Context, Reference) (string, error)
}
```

Only the in-memory `SyntheticProvider` is wired. It generates 32 random bytes per
reference, returns hex, has no filesystem mapping or persistence, and respects
context cancellation. Errors from arbitrary providers are converted to bounded
categories, never forwarded as diagnostic strings. Other formats/providers
require a future reviewed contract, not silent compatibility assumptions.

## Independent-process demo

`cmd/broker`, `cmd/consumer`, and `cmd/synthetic-service` are separate Go
commands. `cmd/demo` is a development supervisor that starts each command
independently and passes bounded, one-line synthetic bootstrap data through
stdin pipes. Generated keys and credentials remain in process memory; the
supervisor necessarily holds the synthetic fixture while coordinating the
demo. The consumer reads `examples/consumer.json`, which contains only the
reference. Broker resolution still uses the unchanged `/v1/resolve` mTLS API.

The synthetic service is a separate loopback HTTP challenge verifier. The
consumer sends a one-time HMAC proof, not the credential. This service protocol
is demonstration-only and is not a production service-authentication design.
The stdin bootstrap is not OS-native IPC, user enrollment, process attestation,
or a supported identity boundary. No distinct OS accounts are created or tested.

## Resource limits

16 live pre-TLS connections, 8 active handler resolutions, 4 KiB header setting,
1 KiB request body, JSON nesting depth 8, 2 KiB response parsing bound.
Header timeout 1s, read timeout 2s, write timeout 4s, idle timeout 2s;
provider deadline 2s, client overall timeout 8s, graceful shutdown budget 5s.
Go's HTTP parser includes internal buffering beyond MaxHeaderBytes; that setting
is not an exact total per-connection memory cap. Pending sockets use OS backlog.
Providers must honor context; arbitrary blocking Go functions cannot be safely
killed. Resource bounds reduce abuse, not prevention of local denial of service.

## Event schema v1

`schema_version`, `timestamp` (UTC RFC3339Nano), `event_type`, `request_id`,
optional `principal_id`/`reference_id` (HMAC-SHA256 per-run pseudonyms),
`authentication_method` (`mtls-uri-san`), `policy_decision`
(`allow`, `deny`, `not_evaluated`), `provider_id` (`synthetic`), `status`,
optional `error_category`, `agent_version`, `mode` (`enforcement`).

Statuses: `started`, `stopped`, `resolved`, `invalid_request`,
`invalid_reference`, `authentication_denied`, `policy_denied`,
`secret_not_found`, `provider_unavailable`, `broker_busy`, `internal_failure`,
`canceled`, `delivery_failed`, `transport_failure`.
`resolved` records successful policy/provider resolution and a **release
attempt**, emitted before response. It does not prove receipt or credential use.
Provider failures after permission do not record `allow`, so event consumers
must not infer denied policy from `not_evaluated`.
No credential, token, key, raw certificate, environment or raw reference is
included. IDs cannot correlate across runs. Output has no integrity/durability
guarantee; a successful writer return is not fsync or SIEM acknowledgment.
