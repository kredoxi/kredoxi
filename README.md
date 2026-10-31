# Kredoxi synthetic MVP

Kredoxi replaces credentials in configuration with non-secret references, then
resolves them through an authenticated and policy-authorized runtime boundary.
This repository demonstrates a narrow **development-only** slice, not a
production vault, transparent interception agent or tamper-resistant service.
Licensing is undecided; no license or redistribution grant is added.

## Quick start

Install **Go 1.27.3 or newer patched supported Go**. The module minimum requests
1.27.3 with automatic Go toolchain selection if the installed Go is older.
No external runtime modules, cloud services or real credentials are required.

```powershell
go test ./...
go vet ./...
go run ./cmd/demo
```

The demo generates random credentials, an ephemeral private CA and short-lived
client/server keys **in memory**. It embeds the original
[consumer configuration](examples/consumer.json), which contains only
`kredoxi://v1/demo/example/password`. It starts a loopback TLS 1.3 broker,
authenticates a consumer certificate, authorizes the reference and demonstrates
credential use through an HMAC challenge verified by a synthetic service.
An independently enrolled unauthorized caller is denied; unavailable provider
and stopped broker produce explicit failures. The executable exits nonzero if
any expected result differs.

JSON-line security events go to stdout; fixed demonstration messages go to
stderr. No resolved credential is printed. No environment, browser, local vault,
personal key store or cloud account is read by the demo.

## Integration boundary

This is an **explicit Go resolution API**, not automatic substitution when an
arbitrary application reads `.env` or JSON. A consumer must integrate
`Client.Resolve(ctx, reference)` or `Consume`. The demonstration hosts the broker,
consumer and service in one executable and uses real authenticated TLS requests;
it does not prove cross-process enrollment or OS identity enforcement.
Certificate possession is key-holder identity, **not executable identity**.

See [protocol](docs/protocol.md), [architecture decision](docs/adr-0001.md),
[security evidence and limitations](docs/security.md) and [roadmap](ROADMAP.md).

## Validation

```powershell
go test ./...
go test -race ./...
go test ./internal/resolver -run '^$' -fuzz FuzzReference -fuzztime 5s
go test ./internal/resolver -run '^$' -fuzz FuzzRequestJSON -fuzztime 5s
go vet ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...
```

The race detector needs cgo and a C compiler (available in the Linux CI runner,
not this initial Windows validation host). The vulnerability scanner is pinned
validation tooling, not a runtime dependency.

CI builds/tests on Linux and Windows, runs Linux race/fuzz tests, checks
formatting, scans vulnerabilities, checks artifact integrity and validates cARL
with a SHA-256-verified v1.0.2 binary. It has a read-only token, no publishing
steps and no production secrets. Branch/ruleset enforcement is administered
separately; the existence of this workflow does not prove required checks.

## Governance

cARL v1.0.2 is installed and production Copilot adapters synchronized.
The `go-mvp` profile applies all core controls plus Go, PowerShell and CI packs.
Other shipped conditional packs are installed but inactive, not removed.
User-owned product controls supplement untouched managed baseline artifacts.
Use the actual v1.0.2 executable; a bare `carl` may resolve to an older install.

```powershell
carl status
carl pack effective
carl trace
carl harness status
```

These diagnostics validate artifact health and pack composition, not proof of
model adherence or enforcement of every prose instruction.
