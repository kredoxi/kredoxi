# Reconcile the managed cARL trust-boundary artefact

## Goal

Remove the cARL v1.0.2 managed-artifact drift without losing Kredoxi-specific
security requirements. Keep this governance correction in a separate,
reviewable commit from Core PR A's IPC experiment implementation.

## Evidence before remediation

- The official `carl_1.0.2_windows_amd64.zip` release archive was downloaded
  from the `goldjg/cARL` v1.0.2 release and matched its published SHA-256:
  `6dd84dcbe48493e5a12a072e32ac2c22823260d17254f9c9072b3cae02e2bc7c`.
- The extracted official `carl.exe` hash was
  `11be22594da46a3b2cdaa28b48e3bc877b8125ec8cfabf4810c9f9748c74ee2d`,
  matching the already installed executable. It reports tag `v1.0.2`,
  commit `5e60b70fc45d7ec036c6b3e702a9a01bced223d9`.
- The canonical embedded artifact is
  `embedded/assets/.github/carl/trust-boundaries.md` at that cARL commit.
  Its SHA-256 is
  `2e51cd2b7a0a4fb7c574096702766148bd62d6058d3336ea58fe43179250df37`.
  The current Kredoxi worktree file SHA-256 is
  `3496ba43864944ca38015f25819cbece9e7cac3a408764f04aa15a1d675e55ca`.
- The repository runtime is cARL `1.0.2`, source `goldjg/cARL`,
  `v1.0.2` / commit `5e60b70fc45d7ec036c6b3e702a9a01bced223d9`, installed at
  `2026-10-31T15:30:26.9086075Z`; `managedArtifacts` includes
  `.github/carl/trust-boundaries.md`. It contains no per-file hash and
  `.github/carl/installed-packs.json` is absent.
- cARL v1.0.2 `internal/repair.CompareFile` compares current bytes to embedded
  bytes using `bytes.Equal`; `carl status` is not reporting a hash mismatch
  from a different toolchain. The official v1.0.2 binary reports exactly one
  drifted artefact: `.github/carl/trust-boundaries.md`.
- Kredoxi PR #4 (`Add independent-process synthetic demo`, merged 2026-10-31)
  added the project-specific trust-boundary text in commits
  `7cbe753f79a4f7bbe9464ae8df00d48802407d42` and
  `6d057b62c7a5585365dd47c73af7e25a22de9e01`. Git blame attributes the
  synthetic-bootstrap row and demo bootstrap/containment notes to those
  commits. Their timestamps are after the runtime's recorded installation.
- The project-specific requirements are already preserved in the user-owned,
  unmanaged `.github/carl/kredoxi-controls.md`, under “Invariants” and “Runtime
  boundaries.” The runtime manifest does not list this file as managed.

## Scope and constraints

- Restore only `.github/carl/trust-boundaries.md` to the verified canonical
  cARL v1.0.2 embedded bytes.
- Preserve the Kredoxi bootstrap and process-containment requirements in
  `.github/carl/kredoxi-controls.md`; do not weaken or duplicate them in another
  managed file.
- Do not run `carl repair`, `carl init`, or another broad synchronization
  command.
- Do not alter cARL selection, runtime metadata, instruction packs, adapters,
  production code, or ADR status.

## Validation

After restoration, compare the managed file's SHA-256 with the canonical
embedded artifact and run the official cARL v1.0.2 binary:

- `carl status`
- `carl pack effective`
- `carl trace`
- `carl harness status`

The expected result is a healthy status with no missing or drifted artefacts,
the same effective `go-mvp` pack set, no policy conflicts, and all harness
adapters healthy. The repository governance CI job must run on the subsequent
Core PR. Retain the IPC experiment's independent commit and its separately
recorded platform-validation limits.

## Outcome

The only content differences were the Kredoxi bootstrap row and the two
Kredoxi-specific demo bootstrap/process-containment bullets introduced by Core
PR #4. The existing project-owned `kredoxi-controls.md` already preserves those
requirements, so it was left unchanged. Only the duplicate additions were
removed from the managed file.

After restoration, the managed file's SHA-256 is
`2e51cd2b7a0a4fb7c574096702766148bd62d6058d3336ea58fe43179250df37`, identical
to the canonical embedded bytes. The official v1.0.2 binary reports `Healthy`,
no missing or drifted artefacts, the expected `go-mvp` effective pack set,
zero trace conflicts, and five healthy harness adapters. The repository
governance CI job remains pending the Core PR.
