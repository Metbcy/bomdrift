# Roadmap

What's planned, what's deliberately out of scope, and what the
acceptance criteria for new contributions look like.

## Shipped (v0.8 — supply-chain hardening)

- **SARIF + GitHub Code Scanning** with stable per-result fingerprints
  and one-line action opt-in (`upload-to-code-scanning: true`).
- **EPSS scoring** on every CVE-aliased advisory; `--fail-on-epss`
  threshold gating.
- **CISA KEV flagging** of known-exploited advisories;
  `--fail-on kev`.
- **License allow/deny policy** with `*`-suffix glob matching and
  fail-closed compound-expression handling. New
  `bomdrift.license-violation` SARIF rule.
- **Baseline `expires` + `reason`** for time-boxed risk acceptance,
  with stderr warnings on expired entries.
- **`time` crate adoption + `clock` module** — single source of truth
  for date/time, honors `SOURCE_DATE_EPOCH`.
- **OSV CVE aliases** threaded through `VulnRef` (prerequisite for
  EPSS / KEV / VEX).
- **`--debug-calibration-format jsonl`** alternative to the v0.7
  pipe-delimited format.
- **`--output-file <PATH>`** CLI flag (avoids `>` redirection in YAML).

## Planned (v0.9 — interoperability + breadth)

- **VEX consume** — `--vex <path>` accepts OpenVEX 0.2.0 + CycloneDX
  VEX 1.6 statements; `not_affected` / `fixed` suppress findings,
  `under_investigation` annotates.
- **VEX emit** — `--emit-vex <path>` emits an OpenVEX document from
  baseline-suppressed findings. Defaults to
  `under_investigation` (the safe truth-claim); per-entry
  `vex_status` override required for `not_affected`.
- **SPDX expression evaluator** — replaces v0.8's atomic+glob matcher
  with full `(MIT OR Apache-2.0)` evaluation via the `spdx` crate.
  Deprecates `allow_ambiguous`.
- **Multi-SCM templates** — Bitbucket Pipelines + Azure DevOps with
  per-platform footer shapes and PR-comment upsert recipes.
- **Registry-metadata enrichers** — npm `time.modified`, PyPI
  `info.yanked`, crates.io `versions[].yanked`. New finding kinds:
  `RecentlyPublished`, `Deprecated`, `MaintainerSetChanged`.
- **GitLab in-comment suppression** with explicit security guards
  (token verification, event filter, project allowlist, commenter
  permissions, fork-MR safety). Reference Cloudflare Worker bridge.
- **Explicit non-goals doc** — reachability, tarball static analysis,
  auto-fix PR generation, container image scanning, SAST/secrets,
  risk-score dashboards. Pair with Endor/Snyk for reachability,
  Renovate/Dependabot for auto-fix.

## Future candidates (not committed)

- **GraphQL maintainer-age** — was investigated for v0.4 and deferred.
  The current REST implementation already uses `?per_page=1` + Link-header
  parsing for top contributor and contributor count. The remaining
  round-trip cost is the per-author commit-history pagination, and
  GitHub's GraphQL `history()` connection doesn't expose ASC ordering —
  finding the oldest commit still requires cursor pagination. v0.5 may
  approach this via `User.contributionsCollection` or accept that REST
  is the right tool here.
- **Custom rules / plugin system** — let consumers add
  organization-specific enrichers (e.g. "flag any dep from
  internal-mirror.example.com without a SHA-256 attestation").
  Probably WASM-based for sandboxing.
- **GitLab in-comment suppression** — v0.7 ships the GitLab CI
  template + `--platform gitlab` (the diff path); v0.9 will add the
  comment-driven `/bomdrift suppress <ID>` flow with explicit
  security guards.
- **Calibration tuning from `--debug-calibration` data** — v0.7
  added the diagnostic flag; v0.8 may revise
  `SIMILARITY_THRESHOLD`, `YOUNG_MAINTAINER_DAYS`, and OSV cache
  TTL defaults based on adopter-collected samples shared on
  issue #5.
- **OCI artifact attestation** — verify SBOMs are themselves signed
  by the build system before diffing. Pairs with cosign attest.

### Calibration backlog

These are tunable thresholds where the v0.3 default may not be the
right answer at scale. Adjusting requires real-world signal data, so
they're tracked as "watch the false-positive rate":

- Typosquat `SIMILARITY_THRESHOLD` (currently 0.92).
- Maintainer-age `YOUNG_MAINTAINER_DAYS` (currently 90).
- OSV severity cache TTL (currently 24h).

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
