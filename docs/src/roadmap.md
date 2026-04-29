# Roadmap

What's planned, what's deliberately out of scope, and what the
acceptance criteria for new contributions look like.

## Shipped (v0.9 — interoperability + breadth)

- **VEX consume** — `--vex <path>` accepts OpenVEX 0.2.0 + CycloneDX
  VEX 1.6 statements; `not_affected` / `fixed` suppress findings,
  `under_investigation` annotates.
- **VEX emit** — `--emit-vex <path>` emits an OpenVEX 0.2.0 document
  with explicit per-entry `vex_status` (default
  `under_investigation`, never auto-promoted).
- **Full SPDX expression evaluator** via the `spdx` crate. Deprecates
  `allow_ambiguous`.
- **Bitbucket Pipelines + Azure DevOps Pipelines** templates with
  auto-detection (`BITBUCKET_BUILD_NUMBER`, `TF_BUILD`) and
  per-platform footer shapes.
- **Registry-metadata enrichers** — npm/PyPI/crates.io. New kinds:
  recently-published, deprecated, maintainer-set-changed (npm only).
- **GitLab comment-driven suppression** via a security-reviewed
  Cloudflare Worker reference bridge (five guards).
- **Explicit non-goals + pair-with recommendations** in README and
  STATUS.

## Shipped (v0.8 — supply-chain hardening)

- SARIF + GitHub Code Scanning with stable per-result fingerprints
  and one-line action opt-in (`upload-to-code-scanning: true`).
- EPSS scoring on every CVE-aliased advisory; `--fail-on-epss`.
- CISA KEV flagging of known-exploited advisories; `--fail-on kev`.
- License allow/deny policy with `*`-suffix glob matching and
  fail-closed compound-expression handling. New
  `bomdrift.license-violation` SARIF rule.
- Baseline `expires` + `reason` with stderr warnings on expiry.
- `time` crate + `clock` module honoring `SOURCE_DATE_EPOCH`.
- OSV CVE aliases threaded through `VulnRef`.
- `--debug-calibration-format jsonl` and `--output-file <PATH>`.

## Future candidates (not committed)

- **Per-exception SPDX allow/deny** — currently the WITH-exception
  identity is informational only; allow/deny narrows to base
  license. v1.0 candidate.
- **PyPI / crates.io maintainer-set-changed** — blocked on
  per-version maintainer data in upstream APIs.
- **VEX vocabulary beyond OpenVEX's 8 justifications** — bomdrift
  uses the spec's enum verbatim. If a richer vocab emerges we'll
  follow.
- **GraphQL maintainer-age** — was investigated for v0.4 and
  deferred. Cursor-pagination cost still steers us toward REST.
- **Custom rules / plugin system** — let consumers add
  organization-specific enrichers. Probably WASM-based.
- **OCI artifact attestation** — verify SBOMs are signed by the
  build system before diffing.

### Calibration backlog

Tunable thresholds where the default may not be the right answer
at scale:

- Typosquat `SIMILARITY_THRESHOLD` (currently 0.92).
- Maintainer-age `YOUNG_MAINTAINER_DAYS` (currently 90).
- Registry `MIN_PUBLISHED_AGE_DAYS` (currently 14).
- OSV / EPSS / KEV / Registry cache TTL (currently 24h).

## Non-goals

These are **explicit non-goals**. Don't open a PR for them — it'll be
declined.

### SBOM generation

bomdrift only **consumes** SBOMs. Use [Syft](https://github.com/anchore/syft)
to generate them — it's already excellent and bomdrift's contribution
would be net-negative.

### Replacing your SCA scanner

OSV-scanner, Grype, Trivy all have richer vulnerability databases and
broader package metadata than bomdrift. **bomdrift's CVE enrichment is
change-focused**: only on what's *new* in this diff. If you want
"what's in my SBOM right now?", run an SCA scanner. If you want "what
changed in this PR's deps that I should worry about?", that's
bomdrift's question.

### Dependency-tree visualization

[`cargo tree`](https://doc.rust-lang.org/cargo/commands/cargo-tree.html),
[`pnpm why`](https://pnpm.io/cli/why), and ecosystem-specific
equivalents handle this well. bomdrift's diff core could in principle
walk the `dependencies` / `relationships` arrays from the source
SBOM, but it's outside the "what's risky" scope.

### Per-language deep parsing

bomdrift treats SBOMs as the source of truth for what's installed.
Walking `package-lock.json` / `Pipfile.lock` / `Cargo.lock` directly
would let us catch things SBOMs miss (lockfile drift), but doubles
the parser surface for marginal signal — and the SBOM-generation
ecosystem is converging fast enough that this won't matter in 18
months.

### Web UI / dashboard

bomdrift is intentionally a CI tool. Long-running stateful
dashboards (org-wide vuln tracking, exception management UI) are
better served by tools designed for that — Anchore Enterprise,
Snyk, etc. The PR comment is the UX.

## Contribution acceptance criteria

A new enricher / output format / parser PR should:

1. **Pass `cargo clippy --all-targets --all-features -- -D warnings`**
   on its own. The codebase is clippy-clean and we keep it that way.
2. **Add unit tests** in `src/<your-module>/tests` covering the
   happy path + at least one edge case. Best-effort enrichers should
   test the network-failure path (via fake fetcher injection).
3. **Add an end-to-end test** in `tests/cli.rs` if it's CLI-visible,
   or `tests/integration.rs` if it's library-internal.
4. **Document its rationale in a module doc comment** at the top of
   the file. The "why" is more interesting than the "what" — future
   contributors lift the rationale, not just the implementation.
5. **Stay best-effort**. Network or filesystem failures must not
   block the diff from rendering. The contract is "render whatever
   we got", not "all-or-nothing".
6. **Not pull in tokio / chrono / semver / octocrab** without strong
   justification. The dep-tree audit is real — see
   [Architecture](./architecture.md#why-no-async--tokio).

See [Contributing](./contributing.md) for the development loop.
