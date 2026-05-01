# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.9.9] - 2026-04-30

The "distribution release." Phase 1 of the bomdrift adoption plan: every
plausible install path now works in one command. The release pipeline
gains four new outputs — crates.io, ghcr.io, SLSA build provenance, and
an automated `v1` major-tag retag — alongside the existing GitHub
Release + cosign-signed archives. No source-code feature work; the
v0.9.9 binary is functionally identical to the v0.9.8 binary.

### Added

- **`cargo install bomdrift` works.** The crate is now published to
  crates.io. Cargo.toml gains `documentation = "https://docs.rs/bomdrift"`
  and a `[package.metadata.docs.rs]` block so the auto-built docs.rs
  page renders cleanly. The published-crate footprint is 54 files /
  220 KiB compressed, achieved via an `exclude` list trimming `tests/`
  (2.7 MB of fixtures), `docs/` (mdbook source), `examples/`,
  `benches/`, `fuzz/`, `comment-suppress/`, `scripts/`, `.github/`, the
  GitHub Action manifests, and the CONTRIBUTING / CODE_OF_CONDUCT /
  STATUS files. `data/` (typosquat reference lists, `include_str!`'d
  at compile time) stays in.
- **`docker run ghcr.io/metbcy/bomdrift:latest` works.** A new
  multi-arch (linux/amd64, linux/arm64) image is published to
  GitHub Container Registry on every release. Single-stage Dockerfile;
  the image consumes the cosign-signed binaries already produced by the
  release matrix — no `cargo build` runs in the image. Distroless cc
  base, runs as the distroless `nonroot` user, ~28 MB. Tag matrix:
  `:vX.Y.Z`, `:vX.Y`, `:vX`, `:latest`. The image carries an inline
  SLSA build provenance attestation (verify with
  `gh attestation verify --owner Metbcy oci://ghcr.io/metbcy/bomdrift:vX.Y.Z`).
- **SLSA build provenance attestations.** Every release archive AND
  the multi-arch ghcr.io image are now covered by
  `actions/attest-build-provenance@v2`. SLSA proves *"this artifact
  was produced by the public release.yml workflow on tag X in this
  repo"*; the existing cosign signatures continue to prove *"the
  bomdrift maintainer's GitHub OIDC identity signed this artifact."*
  Both verifications must pass for the release to be trustworthy. See
  [docs/src/release-signing.md](docs/src/release-signing.md) for the
  full threat-model framing and the
  `gh attestation verify` / `slsa-verifier` recipes.
- **`publish-dry-run` PR-time CI guard.** New `ci.yml` job runs
  `cargo publish --dry-run --locked` on every PR. Catches
  crate-metadata regressions (oversized package, missing required
  fields, an `exclude` list change that drops a build-time
  `include_str!` source) before they reach a release tag.

### Changed

- **README install section ships three new install paths.** `cargo
  install --locked bomdrift`, `docker run ghcr.io/metbcy/bomdrift`,
  and the existing release-archive curl path are now equally
  prominent. The from-source `cargo install --git` path stays as a
  fourth option for adopters who want to track main.
- **README badges expanded.** crates.io, docs.rs, and GitHub
  Marketplace badges added at the top of the README. The CI / Release
  / Docs / License badges are kept.
- **GitHub Marketplace listing description rewritten.** Lead with the
  axios narrative and the maintainer-age heuristic, drop generic
  copy. (Marketplace dashboard edit, not a repo-file change.)
- **Workflows opt into the Node.js 24 runner ahead of GitHub's
  2026-06-02 forced-default.** Every workflow now sets
  `FORCE_JAVASCRIPT_ACTIONS_TO_NODE24: 'true'` at the top-level
  `env:` block, silencing the runner's "Node.js 20 actions are
  deprecated" warning that was firing on every `actions/checkout`,
  `upload-artifact`, and sticky-pull-request-comment step. Covers
  `ci.yml`, `docs.yml`, `fuzz.yml`, `release.yml`, and
  `sbom-diff.yml`. Remove the env var once Node.js 24 is the default
  runtime (after 2026-09-16 per GitHub's deprecation timeline).
- **`v1` major-version tag is now automated.** A new `retag-major`
  job in `release.yml` force-pushes `v1` to point at the latest
  release on every tag. Until v1.0.0 ships, the floating tag stays
  `v1` (Marketplace already references it); from v1.0.0 onward, the
  job switches to `v${major}`.

### Fixed

- **Coverage-report PR comment no longer autolinks to a fake parked
  domain.** v0.9.8's coverage job uploaded the report under an
  artifact name that ended in a real TLD and rendered the same string
  in its sticky PR comment. Inside GitHub's web UI the backticks made
  it inline code, but email and feed clients re-render comments with
  their own autolinker that ignores backticks, so the bare
  TLD-shaped token got linked to a real, unrelated parked domain and
  produced exactly the kind of supply-chain-credibility hit a security
  tool can't afford. The artifact is now named `coverage-lcov` (the
  on-disk filename is still the standard one, so lcov-consuming tools
  work unchanged), and the comment links directly to the workflow
  run's artifacts tab so users have a real destination to follow.

### Documentation

- **`docs/src/release-signing.md` gains a SLSA provenance section.**
  Frames cosign + SLSA as complementary, with the threat model where
  each catches what the other misses. Includes
  `gh attestation verify` (recommended) and `slsa-verifier`
  (air-gapped) recipes, and the ghcr.io image attestation verification
  path.
- **Rustdoc cleanup.** Eight broken intra-doc links in module-level
  docstrings (`MAX_QUERIES_PER_BATCH`, `SUFFIX_BOOST_SCORE`,
  `run_with`, `eval_leaf`, `LeafOutcome`, `VulnRef`, `Cache::with_root`,
  `crate::run_diff`) were either demoted to backtick-quoted code spans
  (private items not visible to public docs) or fixed to use the
  correct path after the v0.9.8 lib.rs split. Plus one redundant
  explicit link target. `RUSTDOCFLAGS=-D warnings cargo doc --no-deps
  --all-features` now passes; docs.rs auto-build is clean. No public
  API change.
- **README and STATUS.md drift fixed.** Removed STATUS.md's stale
  Marketplace-publication-pending line (the listing has been live
  since v0.9.8). README from-source bumped from v0.9.8 to v0.9.9.

### Tests

- 444 → 444 (no net change). Distribution-release plumbing only.

### Scope notes — what's in v0.9.9 vs deferred

In v0.9.9: crates.io, ghcr.io, SLSA, docs.rs, Marketplace polish,
README badges + new install paths.

Deferred (separate plans, not version-coupled):

- Homebrew tap (`Metbcy/homebrew-tap` + `bomdrift.rb` formula).
- nix flake, AUR PKGBUILD, winget + Scoop manifests.
- README diet (the wall-of-text comparison table moves to
  `docs/src/compare.md`).
- Asciinema demo recorded against `examples/axios-incident/`.

Deferred from v0.9.8 (held for the next code-hygiene release):

- File splits for `vex.rs`, `render/markdown.rs`, `render/sarif.rs`,
  `baseline.rs`, `enrich/typosquat.rs`, `enrich/license.rs`.
- Mutation-testing audit via `cargo-mutants`.
- Coverage `--fail-under-lines` ratchet (planned for "after 2-3
  releases of visibility" — v0.9.9 is the second).

## [0.9.8] - 2026-04-30

The "code-review-driven hardening" milestone. External agent review surfaced
nine recommendations across P1/P2/P3; v0.9.8 takes five of the six high-leverage
items, defers the rest as v1.0+ candidates with explicit rationale.

### Added

- **Continuous parser fuzzing.** New `fuzz/` standalone sub-workspace with
  three `cargo-fuzz` libfuzzer targets (`parse_cyclonedx`, `parse_spdx`,
  `parse_syft`). Each target two-stages JSON validation before invoking the
  bomdrift parser, scoping the fuzz to bomdrift-side parsing rather than
  serde_json's well-tested layer. Seed corpus from `tests/fixtures/`.
  New `.github/workflows/fuzz.yml` runs each target for 60s on PRs touching
  `src/parse/**` or `fuzz/**`, and 600s weekly on a Sunday cron schedule.
  Nightly Rust toolchain pinned per cargo-fuzz convention. Closes the
  textbook "untrusted-input parser" gap for a security tool.
- **CI coverage report.** New `coverage` job in `.github/workflows/ci.yml`
  runs `cargo-llvm-cov`, emits the lcov report as a workflow artifact, and posts
  a sticky PR comment via `marocchino/sticky-pull-request-comment@v2` showing
  line-coverage percentage. **No `--fail-under-lines` gate yet** — coverage
  is informational for v0.9.8/v0.9.9 to establish a stable baseline before
  ratcheting in a later release. CONTRIBUTING.md gains a "Coverage" subsection
  describing the policy.

### Changed

- **`unwrap`/`expect`/`panic`/`todo`/`unimplemented` lints now warn** at
  crate root via `#![warn(clippy::unwrap_used, clippy::expect_used,
  clippy::panic, clippy::todo, clippy::unimplemented)]`. Production code
  audited; the four remaining `.expect()` sites
  (`baseline.rs:389`, `render/json.rs:42`, `render/sarif.rs:84`,
  `vex.rs:932`) are true invariants and gain explicit
  `#[allow(clippy::expect_used, reason = "...")]` annotations citing the
  why. Test modules opt-out via inner `#![allow(clippy::unwrap_used,
  clippy::expect_used)]` (28 modules touched). Zero production `.unwrap()`
  remain.
- **Every `unsafe` block now carries a `// SAFETY:` comment.**
  16 of 23 unsafe sites (the Rust 2024 `env::set_var` wrappers + a few
  test helpers) lacked annotation. Added rationale to each, and enforce
  going forward via `#![warn(clippy::undocumented_unsafe_blocks)]` at
  crate root.

### Refactored

- **`src/lib.rs` 47 KB → 31 lines.** Extracted the 1,300-line `run_diff`
  orchestration into a new `src/run.rs` module. `lib.rs` is now pure
  re-exports + module declarations. Public API surface preserved
  byte-for-byte: external consumers calling `bomdrift::run_diff(...)` get
  the same function via re-export. Behavior-preserving — all 432 tests
  pass without modification beyond import-path updates.

### Documentation

- README.md gains a "Continuous fuzzing (v0.9.8+)" subsection.
- CONTRIBUTING.md gains a "Coverage" subsection.

### Tests

- 432 → 432 (no net change). Refactor commits are behavior-preserving.

### Scope notes — what's deferred to v1.0

The external review surfaced four other recommendations explicitly deferred:

- **Remaining file splits** for `vex.rs` (50 KB), `render/markdown.rs`
  (58 KB), `render/sarif.rs` (48 KB), `baseline.rs` (42 KB),
  `enrich/typosquat.rs` (42 KB), `enrich/license.rs` (34 KB). The lib.rs
  split was the highest-ROI single split; the others can land
  organically as future PRs touch those files.
- **Mutation testing audit** via `cargo-mutants`. High-signal but slow;
  use as v1.0 audit tool, not a CI gate.
- **Calibration FPR docs** — running bomdrift on top-1000 npm + PyPI for
  12 months of releases needs data-collection infrastructure that
  doesn't exist yet. Tracked separately.
- **Coverage `--fail-under-lines` ratchet** — flip on after 2-3 releases
  of visibility.
- **WASM-sandboxed plugin model** — carryover from v0.9.7; conflicts with
  single-binary tenet at current toolchain costs.

## [0.9.7] - 2026-04-29

The "v0.9.6 follow-up backlog" milestone. Five concrete items from the
v0.9.6 release notes' "Suggested next milestone candidates" list shipped
in one polish release: per-exception SPDX inheritance through compound
expressions, the last hardcoded calibration threshold lifted, proper
Windows plugin process timeouts, full `action.yml` parity with the CLI
flag surface, and air-gapped Sigstore documentation.

### Added

- **`--multi-major-delta <u32>`** CLI flag and matching
  `[diff] multi_major_delta` config key (default `2`, validated `>= 1`).
  Lifts the last hardcoded calibration threshold:
  `version_jump::MIN_MAJOR_DELTA`. Raise to reduce false positives on
  legitimate major-version-bump-heavy ecosystems; lower to flag any
  major bump (1.x → 2.x). `--debug-calibration` rows now emit the
  *active* delta rather than the const default.
- **`action.yml` input parity** with the v0.7-v0.9.7 CLI surface.
  Twenty-five new inputs now map to their corresponding CLI flags:
  `vex`, `emit-vex`, `vex-author`, `vex-default-justification`,
  `allow-licenses`, `deny-licenses`, `allow-exception`,
  `deny-exception`, `allow-ambiguous-licenses`, `no-epss`, `no-kev`,
  `no-registry`, `fail-on-epss`, `recently-published-days`,
  `typosquat-similarity-threshold`, `young-maintainer-days`,
  `cache-ttl-hours`, `multi-major-delta`, `before-attestation`,
  `after-attestation`, `cosign-identity`, `cosign-issuer`,
  `require-attestation`, `plugin`. Multi-line inputs (`vex`, `plugin`)
  iterate one flag per non-empty line. Empty inputs contribute no
  CLI args, so existing workflows are byte-identical without changes.
- **Air-gapped / self-hosted Sigstore documentation** in
  `docs/src/attestation.md`. Documents env vars cosign respects and
  bomdrift inherits unchanged: `SIGSTORE_REKOR_URL`,
  `COSIGN_REKOR_URL`, `SIGSTORE_FULCIO_URL`, `COSIGN_FULCIO_URL`,
  `SIGSTORE_OIDC_ISSUER`, `COSIGN_OIDC_ISSUER`, `SIGSTORE_ROOT_FILE`,
  `COSIGN_REPOSITORY`, `TUF_ROOT`. Includes a worked GitHub Actions
  example with internal Sigstore endpoints, key-based attestation
  fallback notes (for true air-gap where keyless OIDC isn't
  reachable), and a 6-item troubleshooting checklist.

### Changed

- **SPDX `WITH`-chain exception inheritance through compound
  expressions.** v0.9.5 added per-exception allow/deny via
  `[license] allow_exceptions` / `deny_exceptions`, but the evaluator
  only checked the immediate atom. v0.9.7 evaluates each leaf in the
  expression tree and combines outcomes via the SPDX crate's native
  AND/OR semantics:
  - `(Apache-2.0 WITH LLVM-exception) AND (BSD-3-Clause)` with
    `deny_exceptions=[LLVM-exception]` is now correctly **denied**
    (the AND-chain inherits the exception denial).
  - `(Apache-2.0 WITH LLVM-exception) OR
    (Apache-2.0 WITH Classpath-exception-2.0)` with
    `allow_exceptions=[LLVM-exception]` (Classpath not allowed) is
    correctly **permitted** (the LLVM branch wins; OR doesn't poison).
  - Single-WITH expressions (no compound) keep the v0.9.5 wording for
    back-compat. Compound violations append `" (in <raw expression>)"`
    so users can locate the offending atom.
- **Plugin process timeout** now uses the `wait-timeout` crate
  (~50kb, `libc`-only transitive). Replaces the v0.9.6 manual
  `Child::try_wait()` polling loop. Behavior unchanged on Unix; on
  Windows the kill-on-timeout path is now first-class instead of
  best-effort. Preserves the existing best-effort failure semantics
  (timeout drops the offending plugin's findings, logs a warning at
  `BOMDRIFT_DEBUG=1`, rest of the report renders).

### Deps

- Added `wait-timeout = "0.2"` to `[dependencies]` for cross-platform
  process timeout in `src/plugin.rs`. Single transitive (`libc`,
  already in tree).

### Tests

- 420 → 432 (+12). Eight new tests cover SPDX `WITH`-chain
  inheritance through every operator combination
  (AND-with-denied-exception, OR-with-permitted-fallback,
  back-compat single-WITH); two tests cover the `--multi-major-delta`
  knob (override default + reflect in `--debug-calibration`); two
  cover the `wait-timeout`-based plugin timeout path.

### Documentation

- `docs/src/cli-reference.md`: new `--multi-major-delta` entry.
- `docs/src/license-policy.md`: new "WITH-chain exception
  inheritance" subsection with three worked examples.
- `docs/src/enrichers/version-jump.md`: Calibration subsection
  rewritten to cover the new knob.
- `docs/src/architecture.md`: `wait-timeout = "0.2"` row added to
  the approved-deps table.
- `docs/src/github-action.md`: action input reference regrouped
  by purpose; "What's new in v0.9.7" subsection added.
- `docs/src/attestation.md`: air-gapped subsection (above).

### Roadmap

This release closes 5 of the 6 "Suggested next milestone candidates"
from v0.9.6's release notes:

| Item | Disposition |
|---|---|
| Per-exception SPDX granularity through `WITH` chains | **Shipped** |
| Multi-major version-jump calibration knob | **Shipped** |
| Windows plugin timeout (proper, not best-effort) | **Shipped** |
| Action.yml parity with newer CLI flags | **Shipped** |
| Cosign air-gapped Sigstore docs | **Shipped** |
| WASM-sandboxed plugin model | **Deferred** (multi-week scope, conflicts with single-binary tenet; v1.0+ candidate if external-process model proves insufficient) |

### Scope notes

- **WASM-sandboxed plugin model** stayed deferred. The external-process
  plugin model from v0.9.6 covers the use case adopters want; WASM
  sandboxing would add a multi-week toolchain overhaul (`wasmtime`
  ~30MB / 80 transitive deps, or `wasmi`'s slower runtime, plus a Rust
  plugin SDK, plus dual-runtime support to not break v0.9.6 plugins).
  Stays a v1.0+ candidate if demand materializes.

## [0.9.6] - 2026-04-29

The "finish the roadmap" milestone. v0.9.6 closes out every entry in the
prior roadmap's "Future candidates (not committed)" section — by shipping
it, by closing it as a non-goal, or by documenting the explicit upstream
blocker. Headline new features: **OCI attestation verification** via
`cosign verify-attestation`, an **external-process plugin system** for
custom rules, full **CLI calibration knobs** for the remaining hardcoded
thresholds, and a **comprehensive documentation refresh** across every
chapter to reflect v0.7 → v0.9.6 reality.

### Added

- **OCI attestation verification.** `bomdrift diff
  --before-attestation <oci-ref> --after-attestation <oci-ref>` shells
  out to `cosign verify-attestation --type=cyclonedx`, parses the
  in-toto envelope, and feeds the verified SBOM payload into the
  standard parser. New `--cosign-identity <regex>` and
  `--cosign-issuer <url>` flags pass through to cosign's
  `--certificate-identity-regexp` / `--certificate-oidc-issuer`. New
  `--require-attestation` boolean refuses falling back to the
  `--before` / `--after` file flags so production CI gates can enforce
  attested SBOMs only. Documented in `docs/src/attestation.md`. New
  `attestation` row in `--debug-calibration` so users can confirm
  cosign accepted the right cert.
- **External-process plugin system.** New `--plugin
  <path-to-plugin.toml>` flag (repeatable). Plugin manifest in TOML
  (`name` / `description` / `exec` / `timeout_ms` / `invoke_on`).
  bomdrift invokes the plugin once per Added or VersionChanged
  component with JSON on stdin (`{component, event, before}`) and
  parses JSON from stdout (`{findings: [...]}`). Best-effort: timeout,
  non-zero exit, or malformed JSON drops the offending plugin's
  findings and logs a warning at `BOMDRIFT_DEBUG=1`; the rest of the
  diff renders. New `bomdrift.plugin` SARIF rule with stable
  `partialFingerprints` per `(plugin_name, purl, rule_id)`. Worked
  example shipped under `examples/plugins/banned-packages/`.
  Documented in `docs/src/plugins.md`. Protocol carries
  `protocol_version: 1` for forward-compat.
- **CLI calibration knobs** for the three previously-hardcoded
  thresholds:
  - `--typosquat-similarity-threshold <FLOAT>` (default `0.92`,
    validated 0.0..=1.0).
  - `--young-maintainer-days <i64>` (default `90`, validated >= 1).
  - `--cache-ttl-hours <u64>` (default `24`, validated >= 1; applies
    uniformly to OSV / EPSS / KEV / Registry caches).
  - Matching `[diff]` config keys: `typosquat_similarity_threshold`,
    `young_maintainer_days`, `cache_ttl_hours`.
  - `--debug-calibration` rows now emit the *active* threshold rather
    than the hardcoded default, so calibration data collection
    reflects the real run.

### Changed

- **`CACHE_TTL_SECS` unified.** Previously duplicated in four
  modules (`src/enrich/{cache,epss,kev,registry}.rs`). Now a single
  source of truth in `src/enrich/cache.rs` with `effective_ttl_secs`
  helper that honors per-run overrides without globals.
- **Comprehensive documentation refresh** across every chapter.
  Notable updates:
  - `README.md` rewritten with capability-grouped feature list
    (Ingest / Enrichers / Suppression / Output / Forge /
    Extensibility / Packaging) and a 5-column comparison table
    against Socket / Snyk / Trivy / OSV-Scanner / Grype with 11
    feature-row dimensions sourced from the v0.7-v0.9 competitor
    research doc.
  - `docs/src/cli-reference.md` rewritten end-to-end. Every CLI flag
    now documented and grouped by purpose (Output / Suppression /
    Enrichment / Calibration / License / Failure thresholds /
    Forge / Attestation / Plugins / Diagnostics) with each entry
    annotated with introduced-in version.
  - `docs/src/architecture.md` module map expanded to cover the 8
    modules added across v0.7-v0.9.6 (`config`, `clock`,
    `attestation`, `plugin`, `vex`, `epss`, `kev`, `registry`,
    `license`); new "Best-effort enricher contract" and
    "Byte-determinism contract" subsections; approved-deps table
    including `base64 = "0.22"` (v0.9.6) and `spdx = "=0.10.9"`
    exact pin (v0.9.5).
  - `docs/src/baseline.md` 6-row schema-reference table for the
    unified `BaselineEntry` (id / purl / expires / reason /
    vex_status / vex_justification).
  - Per-enricher chapters (`docs/src/enrichers/{typosquat,
    maintainer-age,version-jump,kev,epss,registry}.md`) gained
    consistent Calibration + Disabling + See-also subsections;
    overview table grew from 4 to 9 rows.
  - `docs/src/SUMMARY.md` reorganized into Output / Enrichers /
    Suppressions / Advanced groups for new-reader navigation.
  - `CONTRIBUTING.md` "Test conventions (v0.9.5+)" subsection added
    documenting the `clock::test_env_lock()` recipe; "Adding a new
    enricher" and "Adding a new finding kind" worked recipes.
  - Stale content rewritten across multiple chapters
    (`gitlab-ci.md`'s v0.7-deferred section now covers what v0.9
    actually shipped; release-signing pins refreshed; etc.).

### Roadmap

- Closed out every "Future candidates" entry from the v0.9.5
  roadmap with explicit dispositions:
  - **Reachability** → moved to Non-goals (pair with Endor / Snyk).
  - **GraphQL maintainer-age** → decided: REST stays
    (cursor-pagination-cost analysis lifted into the maintainer
    enricher's module doc).
  - **VEX vocabulary beyond OpenVEX 8 justifications** →
    spec-bound; documented in `docs/src/vex.md` that bomdrift
    follows the OpenVEX 0.2.0 vocab verbatim.
  - **PyPI / crates.io maintainer-set-changed** → moved to a new
    "Blocked on upstream" subsection with the precise API gap
    documented (PyPI lacks per-version maintainers; crates.io
    lacks per-version `published_by` history).
- Calibration backlog section removed entirely — every threshold
  (similarity, young-maintainer-days, recently-published-days,
  cache-ttl-hours) is now CLI/config-configurable.

### Deps

- Added `base64 = "0.22"` for the cosign in-toto envelope payload
  decode in `src/attestation.rs`. Already a transitive dep via
  `ureq`; promoted to direct so we own the pin.

### Tests

- 389 → 420 (+31). Plugin manifest parse, plugin success/timeout/
  non-zero-exit/malformed-output paths, attestation envelope parse,
  fake-cosign integration test (PATH-injection with serialized env
  lock), calibration knobs override default + reflect in
  `--debug-calibration`, cache-TTL override per enricher.

### Scope notes

What stayed deferred to v1.0 candidates (carried to roadmap "Blocked
on upstream" or new "Future candidates"):

- PyPI / crates.io maintainer-set-changed (upstream API blockers).
- WASM / sandboxed plugin model (current external-process model
  works; revisit if demand materializes).
- Bitbucket / Azure DevOps action-side `vex:` / `emit-vex:` /
  `plugin:` inputs (CLI surface is broader than action surface).
- Multi-major version-jump `MIN_MAJOR_DELTA` calibration knob
  (only remaining hardcoded threshold; revisit with calibration data).

## [0.9.5] - 2026-04-29

The "polish + multi-SCM parity" milestone. v0.9.5 ships the v0.9 follow-up
backlog that was deferred to v1.0 in the v0.9 changelog: per-exception
SPDX allow/deny granularity, exact-pinning of license-data dependencies,
a public synthetic-id parser for VEX consumers, and — most visibly —
**Bitbucket Cloud and Azure DevOps comment-driven suppression bridges**,
giving bomdrift comment-driven suppression parity across all four major
SCMs (GitHub, GitLab, Bitbucket, Azure DevOps).

### Added

- **Per-exception SPDX allow/deny.** New `[license] allow_exceptions` /
  `deny_exceptions` arrays in `.bomdrift.toml` plus matching
  `--allow-exception` / `--deny-exception` CLI flags. License expressions
  using the `WITH` operator (e.g. `Apache-2.0 WITH LLVM-exception`) are
  now evaluated at the exception level too, not just the base license.
  Fail-closed semantics carry over: if `allow_exceptions` is non-empty
  and the exception is not in it, the package is denied; if
  `deny_exceptions` is non-empty and the exception IS in it, denied.
  Empty lists preserve v0.9 behavior (exception treated as informational).
  Surfaces in `LicenseViolation::matched_rule` as
  `"exception:<id> denied"` / `"exception:<id> not in allow list"` and
  is fingerprinted distinctly from base-license violations in SARIF.
- **Bitbucket Cloud comment-suppress bridge.** New
  `examples/bitbucket-pipelines/comment-bridge/` (Cloudflare Worker
  reference) implementing the same five guards as the GitLab bridge:
  webhook UUID/HMAC verification, event-type filter
  (`pullrequest:comment_created` only), repo allowlist, commenter-
  permission check (Bitbucket Cloud REST API workspace permissions ≥
  `write`), and PR-context guard (rejects fork-PR comment-suppress to
  prevent untrusted forks suppressing findings on upstream).
- **Azure DevOps comment-suppress bridge.** New
  `examples/azure-devops/comment-bridge/` covering the
  `ms.vss-code.git-pullrequest-comment-event` Service Hook with
  parallel guards: header-secret verification, event-type filter,
  project-UUID allowlist, commenter-permission check (Azure DevOps
  identities API), and protected-target-branch guard. Triggers an
  Azure Pipeline run with `BOMDRIFT_NOTE_BODY` template parameter.
- **Public `bomdrift::vex::parse_synthetic_id` helper.** Round-trips
  bomdrift's synthetic finding IDs (`bomdrift.typosquat:<purl>:<closest>`,
  etc.) back to a structured `SyntheticFindingKind` enum. Lets external
  VEX tooling identify which bomdrift finding a VEX statement targets
  without string-splitting. Re-exported from `lib.rs` for downstream
  Rust consumers.

### Changed

- **`spdx` crate exact-pinned to `=0.10.9`.** SPDX list updates can
  shift `LicenseId.is_gnu()` / `is_osi_approved()` membership and
  silently change license-policy semantics. v0.9.5 pins exactly so
  bumps are deliberate; the v0.9 caret pin was changed to exact in
  this release.
- **`BaselineEntry` and `ExpiredEntry` unified.** They overlapped on
  `id`, `purl`, `expires`, `reason`. The two are now backed by a single
  internal type with a status enum; the public `ExpiredEntry` alias is
  preserved for back-compat. No behavior change; warning text on
  expired entries unchanged.
- **CI Rust toolchain pinned to MSRV 1.88.** `dtolnay/rust-toolchain@1.88`
  across all CI workflow jobs. Avoids surprises from newer clippy lints
  (`cloned_ref_to_slice_refs`, `useless_vec`, `is_multiple_of` came in
  Rust 1.94 and broke the v0.8 build until handled). Bump deliberately
  via `Cargo.toml`'s `rust-version` field in lockstep.

### Refactored

- **Single source of truth for the `/bomdrift suppress <ID> [reason: ...]`
  comment grammar.** New `scripts/parse-suppress-comment.sh` is the
  canonical regex; `comment-suppress/entrypoint.sh` sources it,
  `examples/gitlab-ci/comment-bridge/worker.js` mirrors it with a
  pointer comment, and `scripts/check-suppress-regex-sync.sh` is wired
  into CI to fail the build if the shell + JS copies drift. The Rust
  `--from-comment` parser keeps its native regex but now carries a
  doc-comment pointing at the canonical grammar.

### Documentation

- **GitLab note upsert + threading semantics** documented in
  `docs/src/gitlab-ci.md` "How notes are upserted" section. Closes the
  v0.7 plan's open question about whether the `PUT
  /merge_requests/:id/notes/:note_id` upsert preserves reviewer-reply
  threading (it does — note ID stays stable, replies survive, no
  re-fired note hooks for unchanged content).
- **`docs/src/license-policy.md`** extended with the SPDX `WITH`
  exceptions section + worked examples.
- **`docs/src/vex.md`** extended with the synthetic-id grammar and
  `parse_synthetic_id` reference for external tooling authors.

### Tests

- 369 → 389 (+20) — covering exception allow/deny semantics,
  synthetic-id round-trip, baseline-entry-unify regression guards, and
  bridge regex sync checks.

### Scope notes

- The Rust `--from-comment` parser remains its own regex (Rust regex
  syntax differs from POSIX/JS); CI guards the shell+JS copies but the
  Rust copy is doc-linked, not auto-synced.
- PyPI/crates.io maintainer-set-changed enrichment (a v0.9 follow-up
  for parity with the npm enricher) stayed deferred — neither PyPI's
  nor crates.io's REST API exposes maintainer history cleanly.
- Bridge worker.js files stay user-deployed (Cloudflare Worker /
  Vercel / Netlify / AWS Lambda Edge); bomdrift the binary still does
  not run a webhook server.

## [0.9.0] - 2026-05-01

The "interoperability + breadth" milestone. v0.9 adds VEX (Vulnerability
Exploitability eXchange) consumption + emission, full SPDX expression
evaluation, multi-SCM templates (Bitbucket Pipelines + Azure DevOps),
registry-metadata enrichers (npm/PyPI/crates.io), and a security-reviewed
GitLab comment-driven suppression bridge.

### Added

- **VEX consume (`--vex <path>`, repeatable).** Auto-detects OpenVEX
  0.2.0 vs CycloneDX VEX 1.6 per file. Statements with status
  `not_affected` / `fixed` suppress matching findings (counted in the
  new "Suppressed by VEX" markdown summary row); `under_investigation`
  annotates with a `VEX:` badge in markdown and
  `properties.vexStatus` in SARIF; `affected` annotates as a no-op.
  Match keys are `(VulnRef.id OR alias, purl_with_version)` with a
  documented synthetic-id convention for non-CVE finding kinds
  (`bomdrift.<kind>:<purl>:<discriminator>`).
- **VEX emit (`--emit-vex <path>`).** Writes a single OpenVEX 0.2.0
  document covering baseline-suppressed entries (status from the
  per-entry `vex_status`, defaulting to `under_investigation` —
  baseline ≠ "not affected", never auto-promoted) and un-suppressed
  findings (status `affected` with `status_notes` describing the
  finding kind). New baseline fields `vex_status` and
  `vex_justification`. New `[diff] vex_author` and
  `[diff] vex_default_justification` config keys.
- **Full SPDX expression evaluator** via the `spdx = "0.10"` crate.
  Replaces v0.8's atomic+glob matcher: `(MIT OR Apache-2.0)` with
  `allow=[MIT]` permits; `(MIT AND GPL-3.0-only)` with
  `deny=[GPL-3.0-only]` violates; `Apache-2.0 WITH LLVM-exception`
  parses cleanly (base license checked, exception identity
  informational only). Non-SPDX strings fall back to the v0.8
  atomic+glob path. `allow_ambiguous` is deprecated with a one-time
  stderr warning.
- **Bitbucket Pipelines + Azure DevOps Pipelines** support.
  `Platform::Bitbucket` and `Platform::AzureDevOps` variants on the
  CLI; auto-detection via `BITBUCKET_BUILD_NUMBER` and `TF_BUILD`
  envs; `BITBUCKET_GIT_HTTP_ORIGIN` and `BUILD_REPOSITORY_URI`
  honored as `--repo-url` fallbacks. Per-platform footer URL shapes
  (`/issues/new` for Bitbucket; `/_workitems/create` for Azure
  DevOps). Drop-in templates with READMEs in
  `examples/bitbucket-pipelines/` and `examples/azure-devops/`.
- **Registry-metadata enrichers (`src/enrich/registry.rs`).** Three
  best-effort fetchers — npm, PyPI, crates.io — with disk cache at
  `<XDG_CACHE>/bomdrift/registry/<eco>/<pkg>.json` (24h TTL,
  atomic temp-file + rename). Three new finding kinds:
  `RecentlyPublished` (default <14d threshold, tunable via
  `--recently-published-days`), `Deprecated` (npm
  `versions[].deprecated`, PyPI `info.yanked` + Inactive
  classifiers, crates.io `versions[].yanked`), and
  `MaintainerSetChanged` (npm only — PyPI/crates.io don't expose
  per-version maintainers cleanly). New `--no-registry` flag and
  `[diff] no_registry = true` config key. New `--fail-on
  recently-published` and `--fail-on deprecated` thresholds. New
  SARIF rules `bomdrift.recently-published`, `bomdrift.deprecated`,
  `bomdrift.maintainer-set-changed` with stable
  `partialFingerprints.primaryHash/v1`.
- **GitLab comment-driven suppress.** `bomdrift baseline add
  --from-comment <BODY>` parses the raw note body, extracts the
  first `/bomdrift suppress <ID>[ reason: <text>]` directive, and
  fails non-zero with a clear stderr message when no directive is
  found (so a misconfigured webhook bridge fails loudly).
  `examples/gitlab-ci/comment-bridge/` ships a Cloudflare Worker
  reference implementation enforcing five guards: webhook secret
  (constant-time compare), event-type filter, project-ID
  allowlist, commenter access_level >= 30, and an MR-context
  guard that rejects fork-MR exfiltration. Vercel/Netlify/Lambda
  port note included.
- **Explicit non-goals + pair-with recommendations** in README,
  STATUS, and the roadmap. Reachability, tarball static analysis,
  auto-fix PR generation, continuous monitoring, container
  scanning, SAST/secrets, risk-score dashboards, and closed-source
  advisory feeds are deliberately out of scope; each is paired with
  a recommended complementary tool.

### Changed

- OSV cache schema extended with `aliases: Vec<String>` so cache
  hits no longer drop alias data. Old cache entries without the
  field deserialize with an empty vec (graceful migration).
- `Command::Diff` argument is now boxed (`Box<DiffArgs>`) to satisfy
  clippy's large-enum-variant lint after the v0.9 flag growth.
  Internal-only change; no user-facing impact.
- `BaselineAddArgs.id` becomes optional (`Option<String>`) to allow
  `--from-comment` invocations without a positional ID. Existing
  positional callers are unchanged.

### Scope notes (deferred)

- **Per-exception SPDX allow/deny** — the WITH-exception identifier
  is currently informational only; allow/deny narrows to the base
  license.
- **PyPI / crates.io maintainer-set-changed** — blocked on per-version
  maintainer data in upstream APIs.
- **Bitbucket / Azure DevOps comment-driven suppression** — only the
  diff path ships in v0.9; comment-suppress is GitHub-only (and
  GitLab via the bridge).
- **VEX vocabulary beyond OpenVEX's 8 justifications** — bomdrift
  uses the spec enum verbatim; no extension yet.

## [0.8.0] - 2026-04-29

The "supply-chain hardening" milestone. v0.8 finishes SARIF for GitHub
Code Scanning, lights up exploit-prediction (EPSS) and
known-exploited-in-the-wild (CISA KEV) signals on every advisory,
introduces an explicit license allow/deny policy with fail-closed
compound-expression handling, and adds time-boxed risk-acceptance to
the suppression baseline.

### Added

- **SARIF + GitHub Code Scanning end-to-end.** Every result now carries
  a stable `partialFingerprints.primaryHash/v1` hash so Code Scanning's
  alert dedup threads correctly across runs. New action input
  `upload-to-code-scanning: true` wires
  `github/codeql-action/upload-sarif@v3` for one-line opt-in. New
  `--output-file <PATH>` CLI flag avoids YAML `>`-redirection
  quirks. Per-rule fingerprint identity tuples documented at
  [docs/src/sarif.md](docs/src/sarif.md).

- **EPSS scoring (FIRST.org).** Every CVE-aliased advisory surfaces an
  exploitation-probability badge in markdown / terminal / SARIF /
  JSON. `--fail-on-epss <FLOAT>` trips exit 2 when any advisory exceeds
  the threshold. `--no-epss` opt-out + 24h disk cache at
  `<XDG_CACHE>/bomdrift/epss/`. Best-effort: network failure logs at
  `BOMDRIFT_DEBUG=1`, diff still renders.
  [docs/src/enrichers/epss.md](docs/src/enrichers/epss.md)

- **CISA KEV (Known Exploited Vulnerabilities).** A `KEV` flag flips
  on every advisory whose primary id or CVE alias appears in CISA's
  catalog. `--fail-on kev` + `--no-kev` flags. Once-daily catalog
  cache at `<XDG_CACHE>/bomdrift/kev/catalog.json`.
  [docs/src/enrichers/kev.md](docs/src/enrichers/kev.md)

- **License allow/deny policy.** New `[license]` block in
  `.bomdrift.toml` (or `--allow-licenses`/`--deny-licenses` CLI flags
  matching Dependency Review Action names). Atomic exact match +
  `*`-suffix glob (`AGPL-*`); compound expressions like
  `(MIT OR GPL-3.0)` fail closed by default unless
  `allow_ambiguous=true`. Distinct from same-version license drift:
  this is a policy gate. New SARIF rule
  `bomdrift.license-violation`. `--fail-on license-violation` trips
  exit 2. [docs/src/license-policy.md](docs/src/license-policy.md)

- **Suppression expiry + reason.** Each `suppressed_advisories` entry
  may now be the v0.8 object form
  `{id, expires?: "YYYY-MM-DD", reason?: "free text"}`. Expired
  entries surface a stderr warning and stop suppressing; bomdrift
  refuses to load malformed dates. `bomdrift baseline add --expires
  --reason` records the metadata; the `comment-suppress` companion
  action picks up an optional `reason: <text>` line in the trigger
  comment body.
  [docs/src/baseline.md](docs/src/baseline.md#time-boxed-suppressions-expires--reason)

- **OSV CVE aliases threaded through `VulnRef`.** OSV `/v1/vulns/{id}`
  responses now feed CVE aliases into `VulnRef.aliases` (sorted,
  byte-deterministic). EPSS / KEV / future VEX consumption all read
  from `VulnRef::cves()`.

- **`time` crate adoption + `clock` module.** New `src/clock.rs` is
  the single source of truth for date/time across the codebase.
  Honors `SOURCE_DATE_EPOCH` (read per call so test fixtures can vary
  it). All v0.8 features that emit dates / compare dates go through
  this module — reproducible-build contexts stay deterministic.

- **`--debug-calibration-format <pipe|jsonl>`.** New JSONL alternative
  to the v0.7 pipe-delimited calibration tap. Numeric scores stay
  numeric in JSON; severity buckets stay strings. Adding a new
  finding kind is one call to a dispatch helper, not a fork.

### Changed

- `--fail-on any` now also includes KEV-flagged advisories and
  license-violation findings.
- SARIF rule list grew from 5 to 6 (added `bomdrift.license-violation`).

### Scope notes

The following items were deliberately **deferred to v0.9** rather than
half-shipped:

- **GitLab comment-driven suppress.** The `/bomdrift suppress` flow
  works on GitHub via the `comment-suppress` companion action. Porting
  to GitLab needs a webhook bridge with five distinct security guards
  (token verification, event-type filter, project allowlist,
  commenter-permission check, MR-context guard). Shipping the bridge
  without those is a vulnerability — moved to v0.9 with a security
  review milestone.
- **Multi-SCM (Bitbucket + Azure DevOps).** Templates and footer
  shapes need per-platform comment-API exploration; deferred to v0.9.
- **VEX consume + emit.** Both depend on the `time` crate
  foundation that lands here. Consume in v0.9-G; emit in v0.9-H. The
  baseline-expiry + reason fields added in v0.8 feed directly into
  the VEX `status_notes` field when emit lands.
- **SPDX expression evaluator.** v0.8 fails closed on compound
  expressions; v0.9 adopts the `spdx` crate (~30kb) for proper
  evaluation. The `allow_ambiguous` flag becomes redundant at that
  point.

## [0.7.0] - 2026-04-30

The "broaden the platform, polish the edges" milestone. v0.7 takes the
v0.6 policy-config foundation and adds GitLab CI as a first-class
target, closes the open issue backlog around adoption pain points,
and lays groundwork for calibration tuning.

### Added

- **GitLab CI integration.** `bomdrift diff` now renders a
  GitLab-shaped MR-note footer when `--platform gitlab` is set (or
  when `GITLAB_CI=true` is auto-detected). A copy-paste-ready
  template ships under `examples/gitlab-ci/` with a diff job
  (curl + jq upsert against the GitLab notes API), a manual
  suppression job, and a setup README covering the two-token model
  and Self-Managed considerations. Full chapter at
  [docs/src/gitlab-ci.md](docs/src/gitlab-ci.md).

- **`--platform <github|gitlab>` flag** on `bomdrift diff` (also
  loadable from `[diff] platform = "..."` in `.bomdrift.toml`).
  Default is auto-detection from the CI environment with `github`
  as the fallback. Explicit flag always wins.

- **CI auto-detection on GitLab.** When `GITLAB_CI=true` is set,
  bomdrift selects the GitLab footer shape; when `CI_PROJECT_URL`
  is set and `--repo-url` / `BOMDRIFT_REPO_URL` are unset, it's
  used as the footer link target.

- **`--debug-calibration` flag.** Off by default. When set, the
  diff command emits one pipe-delimited record per finding to
  stderr (`kind|key|score|threshold`). Lets adopters dump a
  calibration sample across many PRs and feed back tuning data on
  `SIMILARITY_THRESHOLD`, `YOUNG_MAINTAINER_DAYS`, etc. No
  telemetry — the user owns the file.

- **Typosquat top-package data top-up** for Go (+35 entries from
  CNCF / HashiCorp / gRPC ecosystem / awesome-go), Composer (+43
  from Symfony / Laravel / Doctrine / testing communities), and
  Gem (+44 from Rails ecosystem / dry-rb / API serializers).
  Closes #6, #7, #8.

### Changed

- **Markdown renderer is now platform-aware.** Backward compatible:
  the GitHub footer shape is preserved byte-for-byte for existing
  callers. New `MarkdownOpts.platform` field controls the
  switch; `Default` resolves to GitHub.

- **Better "scan path not found" error in the GitHub Action.**
  `entrypoint.sh` now lists what was actually checked out and
  links to the new monorepo docs section instead of the prior
  one-line "no such file" error. Closes #11.

### Docs

- **GitLab CI chapter** (`docs/src/gitlab-ci.md`) — quickstart,
  token model, suppression paths, Self-Managed notes, what's
  scoped out for v0.7.
- **False-positive triage worked example** in
  `docs/src/baseline.md` (a typosquat misfire with the exact
  baseline entry that suppresses it). Closes #12.
- **Monorepo setup section** in `docs/src/github-action.md`
  covering matrix-per-service patterns and shared-baseline
  pattern. Closes #9.
- **Action-broke troubleshooting checklist** in
  `docs/src/github-action.md` covering the top-N failure modes.
  Closes #13.
- **CLI reference** updated for `--platform`,
  `--debug-calibration`, and the new `BOMDRIFT_REPO_URL` /
  `GITLAB_CI` / `CI_PROJECT_URL` environment variables.

### Tests

- Regression test for `BOMDRIFT_REPO_URL` env-var → footer URL
  plumbing (#10) — previously only the rendering function was
  unit-tested, not the env-to-option plumbing in `lib.rs`.
- E2E tests for `GITLAB_CI` auto-detection and `--platform`
  override.
- Smoke test for `--debug-calibration` stderr output.

### Scope notes

In-comment suppression on GitLab (`/bomdrift suppress <ID>` in an
MR note) is **deferred to v0.8**. GitLab note webhooks have a
different model than GitHub PR comments, and the safe wiring
(rate-limit, fork-MR safety, command parsing, double-trigger
debouncing) is materially harder. v0.7 ships the manual-job path
in `examples/gitlab-ci/suppress.gitlab-ci.yml`, which covers the
same user need without standing up a webhook handler.

## [0.6.1] - 2026-04-29

### Fixed

- **First PR after `bomdrift init` no longer fails when no baseline
  has been suppressed yet.** `bomdrift init` ships a `.bomdrift.toml`
  with `baseline = ".bomdrift/baseline.json"` — the path the
  `/bomdrift suppress` flow writes to. Before this fix, the diff
  hard-failed with `reading baseline file: ... No such file or
  directory` on every PR until a reviewer used the suppress comment
  at least once. Config-derived baseline paths are now tolerant of a
  missing file (the diff runs with no suppressions applied), while
  CLI `--baseline path` keeps its strict typo-detector behavior.

## [0.6.0] - 2026-04-29

### Added

- **Repository policy config (`.bomdrift.toml`).** `bomdrift diff`
  auto-loads `.bomdrift.toml` from the current working directory when
  present, or an explicit file via `--config`. Config can set defaults
  for output format, fail thresholds, baseline path, markdown focus
  mode, and dependency-churn budgets while leaving CLI flags as the
  one-off override path.

- **`bomdrift init` scaffolding.** `bomdrift init` writes a starter
  `.bomdrift.toml`, SBOM-diff workflow, and comment-suppression workflow.
  `--config-only` writes just the policy file; `--force` overwrites
  existing generated files.

- **Diff-budget gates.** `--max-added`, `--max-removed`, and
  `--max-version-changed` exit 2 after rendering when a PR changes more
  dependencies than the configured budget allows.

- **Focused markdown comments.** `--findings-only` keeps the summary and
  risk-bearing sections but omits raw Added / Removed / Version changed
  detail rows for high-churn PRs.

- **License-change threshold.** `--fail-on license-change` exits 2 on
  same-version license drift without also requiring `--fail-on any`.

- **GitHub Action inputs for policy controls.** The action now accepts
  `config`, `findings-only`, `max-added`, `max-removed`, and
  `max-version-changed` and passes them through to the CLI.

## [0.5.0] - 2026-04-29

The adoption milestone: bomdrift now works as a copy-paste GitHub Action,
posts a much more scannable PR comment, supports comment-driven suppression,
and has the repo surfaces first-time OSS users expect.

### Changed

- **`Ecosystem::Other("file")` pseudo-components are now dropped from
  diffs by default.** Syft's `directory` cataloger emits each YAML /
  lockfile / source file in the scanned directory as a synthetic
  component whose ecosystem string is `"file"`. Path differs between
  the PR-head and base-ref checkouts, so each file shows up as both
  Added and Removed in the same diff, drowning real package changes
  in noise. The filter is applied at the CLI layer, after parse —
  the `bomdrift::parse` library API still returns whatever the SBOM
  format declares.

  This is a visible default-output change but not a breaking one:
  pre-v0.5 baselines that captured `file:` entries continue to load
  (the baseline parser is forgiving) and the entries simply become
  inert, matching against findings that no longer surface.

### Added

- **Zero-config GitHub Action invocation.** `Metbcy/bomdrift@v1` can now
  run on a `pull_request` workflow with no explicit checkout, Syft step,
  or SBOM path wiring. The action checks out the PR base and head refs,
  installs Syft via `anchore/sbom-action/download-syft@v0`, generates
  CycloneDX JSON SBOMs for both sides, runs `bomdrift diff`, and upserts
  the markdown result as a PR comment. Existing `before-sbom` /
  `after-sbom` inputs remain supported as the bring-your-own-SBOM escape
  hatch, but are no longer required.

- **`bomdrift baseline add <id>` CLI subcommand** for adding wildcard
  advisory suppressions to `.bomdrift/baseline.json`. The command creates
  the file and parent directory when missing, writes atomically, and is
  idempotent when the advisory is already suppressed.

- **Companion `Metbcy/bomdrift/comment-suppress@v1` action** for
  in-comment suppression. A reviewer can comment `/bomdrift suppress
  <ID>` on a PR; the sub-action validates the command, runs
  `bomdrift baseline add <ID>`, commits the baseline update to the PR
  branch, and reacts to the trigger comment.

- **`--include-file-components` flag** on `bomdrift diff` for users
  who want the raw cataloger output (debugging, auditing). Off by
  default; enabling it restores the pre-v0.5 behavior.

- **Markdown comment is now collapsible.** Each per-category section
  (Added / Removed / Version changed / Vulnerabilities / Possible
  typosquats / Multi-major version jumps / Young maintainers /
  License changed) is wrapped in a `<details><summary>` block. The
  `### Section (count)` header stays visible above the wrapper so
  the table of contents still works; the body is hidden by default
  for skim-readability on big diffs. Reviewers expand the sections
  they care about.

- **Severity-sorted vulnerability rows.** Within the Vulnerabilities
  section, components are ordered by their highest-severity
  advisory (Critical first, then High / Medium / Low / None), with
  alphabetical tie-breaking on ecosystem+name. Per-component
  advisories continue to be severity-then-id sorted as before.
  Critical / High findings now cluster at the top of the table —
  the load-bearing rows that justify a reviewer's attention.

- **`<summary>` teasers** on the Vulnerabilities and Possible
  typosquats sections surface the most-actionable item without
  expanding (e.g. `top severity: CRITICAL (CVE-2025-foo)` or
  `top similarity: 0.95 (axiosx → axios)`).

- **Per-section "Why this matters" links** in the markdown output,
  reusing the SARIF rule helpUris that v0.4.2 introduced. Reviewers
  click through to the docs chapter explaining what the enricher is
  detecting and why.

- **`--repo-url` flag** (also reads `BOMDRIFT_REPO_URL` env var) on
  `bomdrift diff`. When set, the markdown comment renders an
  action-affordance footer with three links: a pre-filled "Report
  this finding" issue URL, the `/bomdrift suppress <id>`
  suppress-comment hint, and the docs site. The action sets this
  automatically from the consuming repository, while standalone CLI
  runs can pass the flag or env var explicitly. When unset, the footer
  is omitted entirely so forks / standalone CLI use don't render dead
  links to bomdrift's own issue tracker.

- **OSS adoption surfaces.** The README now leads with the one-step
  workflow, a comparison table, suppression setup, and v0.5 examples.
  The repo also has issue templates, a pull-request template,
  root-level CONTRIBUTING.md, CODE_OF_CONDUCT.md, STATUS.md, and a
  pinned feedback issue for early users.

## [0.4.4] - 2026-04-28

The "make the action actually produce output" patch release. Sister
fix to v0.4.3, which fixed the action manifest's location but left
two upstream bugs that prevented bomdrift from running at all once
the manifest was found.

### Fixed

- **`log()` and `endlog()` now write workflow-command directives to
  stderr instead of stdout.** The functions are called from inside
  `download_bomdrift()` whose stdout is captured by the caller
  (`bin="$(download_bomdrift ...)"`) and from inside `run_diff()`
  whose stdout is tee'd into the PR comment body. Writing
  `::group::...` directives to stdout meant:

  1. `$bin` became a concatenation of `::group::bomdrift:
     Downloading...` + cosign's "Verified OK" + `::endgroup::` +
     the actual binary path. Bash then tried to exec a "command"
     called `::group::bomdrift: Downloading...` and reported
     `File name too long`, so bomdrift never actually ran.
  2. The PR comment body ended up as
     `<!-- bomdrift:diff -->\n::group::bomdrift: Running ...\n::endgroup::`
     — just the action's own log markers wrapped around an empty
     body, since the binary never produced output.

  GitHub Actions parses workflow commands from BOTH stdout and
  stderr, so the UI grouping is preserved while the captured
  streams stay clean for the data they're carrying.

- **`download_bomdrift()` now redirects its entire work region to
  stderr via `exec 3>&1 1>&2`, restoring stdout only for the final
  `printf '%s' "$bin"`.** Catches every other stdout-leaking
  command in the function — cosign's "Verified OK", any future
  curl progress modes that route to stdout, tar's verbose output if
  someone adds `-v`, etc. The captured-bin-path value is now
  guaranteed to be the binary path and nothing else.

This bug has been latent since the action shipped in v0.1.0; v0.4.3
was the first release where someone actually invoked the action and
hit it (bomdrift's own dogfood workflow on PR #1).

## [0.4.3] - 2026-04-28

The "make the action actually invokable" patch release. No new
features; fixes a layout bug that has silently broken every consumer
trying to use `Metbcy/bomdrift@v1` since v0.1.0 was tagged.

### Fixed

- **`action.yml` moved from `action/action.yml` to the repo root.**
  GitHub Actions resolves a composite action's manifest at the repo
  root by default; subdirectory actions require consumers to type
  `Metbcy/bomdrift/action@v1` instead of `Metbcy/bomdrift@v1`. Every
  example in the README and docs site used the latter form, so any
  consumer copying those snippets hit:

  ```
  Can't find 'action.yml', 'action.yaml' or 'Dockerfile' for action
  'Metbcy/bomdrift@v1'.
  ```

  The bug surfaced when bomdrift's own dogfood workflow (introduced
  in `60e772d`) tried to self-invoke `Metbcy/bomdrift@v1` and
  failed for the same reason. With the manifest at the repo root,
  `Metbcy/bomdrift@v1` (the form the docs always advertised) now
  works. `entrypoint.sh` moved alongside it; the
  `${{ github.action_path }}/entrypoint.sh` reference continues
  to resolve correctly because that variable points at whatever
  directory contains the loaded `action.yml`.

  Note: this is a v0.x patch release, so the layout change is fine
  for existing consumers who pinned to a prior tag (those tags still
  work as they always did — broken). v1.0 will keep `action.yml` at
  the root permanently.

## [0.4.2] - 2026-04-28

The "fix the broken help links" patch release. No new features, no
behavior change beyond the URLs that finding consumers click through.

### Fixed

- **SARIF `helpUri` fields point to real docs pages.** Every rule's
  `helpUri` previously pointed to a README anchor like
  `https://github.com/Metbcy/bomdrift#cve-enrichment` that didn't
  exist — the README never had those exact heading texts, so the
  link silently scrolled nowhere when a user clicked through GitHub
  Code Scanning's UI for a `bomdrift.cve` finding (or any other
  bomdrift rule). Now point at the corresponding chapter on the
  mdBook docs site:
  - `bomdrift.cve` → `enrichers/osv-cve.html`
  - `bomdrift.typosquat` → `enrichers/typosquat.html`
  - `bomdrift.version-jump` → `enrichers/version-jump.html`
  - `bomdrift.young-maintainer` → `enrichers/maintainer-age.html`
  - `bomdrift.license-change` → `output-formats.html#sarif-v210`
    (no dedicated chapter; the SARIF rule listing is the
    closest user-facing reference for this rule's semantics).
- **SARIF `tool.driver.informationUri`** changed from the GitHub
  repo root to the docs site. SARIF spec defines this as "the
  absolute URI of the tool's website" — the docs site is the
  user-friendly destination from a Code Scanning UI click.
- **Broken anchor in `docs/src/output-formats.md`**: a CHANGELOG
  cross-reference used `#breaking-output-shape` but the actual
  GitHub heading-slug for that section is
  `#changed-breaking-output-shape`. Now matches reality.

## [0.4.1] - 2026-04-28

The "harden the foundations" patch release. No user-visible behavior
change, no new features — pure quality / regression-coverage
improvements that catch entire classes of bugs in advance.

### Added

- **Criterion benchmarks** for the four hot paths: parse, diff,
  typosquat, render. Run with `cargo bench`. Not gated in CI (shared
  GitHub runner variance is ±20%, which buries any real signal); the
  HTML report at `target/criterion/report/index.html` is the workflow
  for validating perf-relevant changes locally. Documented in the
  new [Benchmarks](https://metbcy.github.io/bomdrift/development/benchmarks.html)
  chapter.
- **Property-based tests** via `proptest`, running as part of
  `cargo test --release`. 14 new property tests cover:
  - Parser layer: arbitrary bytes / arbitrary JSON / arbitrary JSON
    with each format hint forced — must NEVER panic. Errors are fine;
    panics are bugs.
  - Typosquat canonicalization: `pep503_normalize` on arbitrary
    unicode (output invariants asserted: lowercase, no leading/
    trailing dashes); `last_path_segment` always returns a substring
    with no `/` in it; `enrich()` never panics on arbitrary added-
    component sets.
  - Diff core: `diff(a, a)` is always empty (identity);
    `diff(a, b)` swaps `added`/`removed` cardinalities from
    `diff(b, a)` (symmetry); two `diff()` calls on the same input
    are byte-equal (determinism — the upsert contract for PR-comment
    renderers).
  - Version-jump extractor: never panics on arbitrary strings;
    round-trips well-formed numerics (`1..10000` with `v`-prefix
    and pre-release suffix variants); handles arbitrary unicode
    prefixes without panic.
- **Real-world SBOM regression corpus** at
  `tests/fixtures/real-world/` containing 4 CycloneDX SBOMs (cern,
  dropwizard, keycloak, laravel) and 1 SPDX SBOM (example10),
  sourced from the official `CycloneDX/sbom-examples` and
  `spdx/spdx-examples` repos. Tests in `tests/real_world.rs` exercise:
  - Every fixture parses without error and to ≥ 1 component.
  - Format auto-detection routes to the correct parser.
  - Components with known purl types resolve to the canonical
    `Ecosystem` variant (catches `ecosystem_from_purl` regressions).
  - Diff of two unrelated real SBOMs doesn't panic.
  - Self-diff of any real SBOM produces an empty ChangeSet
    (parser non-determinism guard).
  - All four renderers produce non-empty output on a real diff.

### Changed

- **Test count**: 236 → 256 passing (226 unit + 15 cli + 9 integration
  + 6 real-world).
- New `[dev-dependencies]`: `criterion = "0.5"` and `proptest = "1"`.
  No effect on the production binary; release-profile size stays at
  ~3.5 MB.

## [0.4.0] - 2026-04-28

The "more ecosystems, more action surface" release. Adds four typosquat
ecosystems (Go, RubyGems, NuGet, Composer), plumbs `--baseline` into the
GitHub Action input surface, and refreshes the docs site to match.

### Added

- **`baseline:` action input** — passes straight through to
  `bomdrift diff --baseline <path>`. Previously consumers wanting baseline
  suppression had to bypass the action and call the binary directly via a
  custom step; the action now handles it. The file's existence is
  validated up front (a typo'd path no-op'ing would defeat the point).
- **Typosquat detection for Go, RubyGems, NuGet, and Composer.** The
  v0.2 multi-ecosystem expansion shipped npm + PyPI + Cargo + Maven; v0.4
  rounds out the JVM-adjacent and dynamic-language pillars. Per-ecosystem
  rules:
  - **Go** matches on the **last path segment** of `host/owner/repo`
    (`github.com/attacker/cobra` flagged against `github.com/spf13/cobra`).
    Same-segment-different-org is treated as a legitimate fork and not
    flagged.
  - **Gem** uses standard JW + suffix-containment with `-` and `_`
    separators (`railz` flagged against `rails`; `rspec-rails` extension
    pattern not flagged).
  - **NuGet** canonicalizes IDs to lowercase per the package-spec's
    case-insensitivity (`Newtonsoft.Json` ≡ `newtonsoft.json`); `.` is
    the separator (`Microsoft.Extensions.Logging` shape).
  - **Composer** matches on the **package portion** of `vendor/package`
    (symmetric to the Maven artifactId-only rule) — `attacker/consolee`
    flagged against `symfony/console`; `myorg/console` is a legit fork.
- **`Ecosystem::Gem`, `Ecosystem::NuGet`, `Ecosystem::Composer`** model
  variants. Components whose purl now resolves to one of these will
  serialize their `ecosystem` field as the canonical name (`gem`,
  `nuget`, `composer`) rather than falling back to the
  `Other("gem")`-as-string representation. JSON / SARIF / markdown
  output all reflect this shape change.
- **`bomdrift refresh-typosquat --ecosystem`** now accepts `nuget`
  (real fetcher; uses the v3 search API
  `?orderby=totalDownloads&take=200`), `go`, `gem`, and `composer`.
  The latter three are no-ops with informational notices: pkg.go.dev,
  rubygems.org, and packagist.org all lack stable public popularity
  feeds, so the curated `data/{go,gem,composer}-top200.txt` snapshots
  shipped in the binary remain the source of truth. Adding a name
  to those lists is an explicit editorial decision; PRs welcome.
- **Embedded data files**: `data/go-top200.txt` (~140 module paths
  curated from pkg.go.dev and well-known imports — cobra, gin, grpc,
  k8s, prometheus, opentelemetry), `data/gem-top200.txt` (~185 well-
  known gems — rails, rspec, devise, sidekiq), `data/nuget-top200.txt`
  (200 IDs auto-fetched from the v3 search API), and
  `data/composer-top200.txt` (~140 `vendor/package` coords — symfony,
  laravel, doctrine).

### Changed

- **`--ecosystem all`** for `refresh-typosquat` now expands to **eight**
  ecosystems (npm, PyPI, Cargo, Maven, Go, Gem, NuGet, Composer)
  instead of four. Network egress increases proportionally; pin to a
  specific `--ecosystem <name>` if you need the v0.3 behavior.

### Deferred to v0.5

- **GraphQL maintainer-age** was investigated for v0.4 and deferred. The
  current REST implementation already uses `?per_page=1` + `Link: rel=
  "last"` parsing for both top contributor and contributor count, so
  the only remaining round-trip cost is the per-author commit-history
  pagination — and GitHub's GraphQL `history()` connection doesn't
  expose an ASC ordering, so the GraphQL replacement would still need
  cursor-based pagination to find the oldest commit (same shape as
  REST). Will revisit if a v0.5 contributor finds a clean approach,
  e.g. via `User.contributionsCollection`.

### Migration notes

- The serialized `ecosystem` field for components with
  `pkg:gem/...`, `pkg:nuget/...`, or `pkg:composer/...` purls
  changes from the v0.3 fallback (`"library"` or `"gem"` as the
  `Other(...)` string) to the v0.4 canonical name. Consumers that
  pinned on the v0.3 string need to migrate.

## [0.3.0] - 2026-04-28

The "severity, baselines, and big-PR survival" release. Closes the v0.2
deferral on real OSV severity, adds an on-disk severity cache, surfaces
baseline-suppression for adoption-mid-stream teams, and stops big PR
diffs from blowing past GitHub's comment-body cap.

### Added

- **Per-advisory OSV severity** via `/v1/vulns/{id}` follow-up. Severity
  is sourced from GHSA's `database_specific.severity` text label
  (`LOW|MODERATE|HIGH|CRITICAL`); advisories without that field surface
  as `NONE` and don't trip `--fail-on critical-cve`. The label is
  rendered alongside each advisory ID in markdown / terminal / JSON /
  SARIF output. SARIF results map Critical/High to `level: "error"`,
  everything else to `level: "warning"`. Markdown / term sort
  highest-severity-first within a component, ties broken by ID, so the
  rendered output stays byte-deterministic for the PR-comment upsert.
- **`--fail-on critical-cve` is now real.** Previously aliased to `cve`
  with a v0.2 stub warning; now filters on `severity >= High` per the
  OSV-fetched severity. The `critical-cve` name covers the
  HIGH-or-CRITICAL bucket (CRITICAL is rare in GHSA tagging; many
  actively-exploited advisories ship as HIGH, and treating them as the
  actionable bucket matches what the option name communicates).
- **On-disk OSV severity cache** at `<XDG_CACHE_HOME>/bomdrift/osv/`
  with a 24h TTL. New `--no-osv-cache` flag opts out. Hits are reported
  via a single end-of-run "osv: N/M severities served from cache"
  stderr line. Atomic temp-file + rename writes mirror the existing
  `src/refresh.rs` pattern.
- **`--baseline <path.json>`** suppresses findings already present in a
  previously captured `bomdrift diff --output json` snapshot. Match
  keys are conservative — drift surfaces — so adopting bomdrift on a
  project with pre-existing findings doesn't drown the first PR
  comment. See `src/baseline.rs` module doc for per-finding-type key
  semantics.
- **`--summary-only`** flag emits only the summary table + a footer
  pointing reviewers at the full output. Markdown-only.
- **Action input `comment-size-limit`** (default 60000 bytes; just
  under GitHub's 65536-char comment cap so a marker + footer fit).
  When the rendered diff exceeds the limit, `entrypoint.sh`
  re-renders with `--summary-only` for the PR comment while keeping
  the full body in the workflow step summary. Set to 0 to disable.

### Changed (breaking output shape)

- **`Enrichment.vulns` JSON shape** is now
  `{"<purl>": [{"id": "...", "severity": "..."}, ...]}` instead of
  `{"<purl>": ["GHSA-..."]}`. Consumers parsing the v0.2 string-list
  shape need to migrate. The CLI wrapper for downstream tooling can
  pin `--baseline` files to v0.3 — the baseline parser is forgiving
  about missing fields, so old baselines still load (with reduced
  suppression precision for the severity-aware fields).

### Fixed

- The action's `entrypoint.sh` now uses `tee` + `PIPESTATUS` so PR
  comments still post when bomdrift exits 2 from `--fail-on`. (This
  was already true in v0.2; the v0.3 size-fallback path follows the
  same pattern when re-running with `--summary-only`.)

## [0.2.0] - 2026-04-28

The "ship the deferred gaps" release. Every "Known gaps (deferred to v0.2)"
bullet from v0.1.0 is now closed, plus several quality-of-life fixes that
surfaced during the v0.1.0 code review.

### Added

- **SARIF v2.1.0 renderer** (`--output sarif`). Emits one result per finding
  with five stable rule IDs (`bomdrift.cve`, `bomdrift.typosquat`,
  `bomdrift.version-jump`, `bomdrift.young-maintainer`,
  `bomdrift.license-change`) suitable for ingestion by GitHub Code Scanning,
  GitLab Vulnerability Reports, etc. All results are `level: warning` in
  v0.2 (severity data isn't yet returned by OSV's `/v1/querybatch`).
  Output is byte-deterministic (HashMap keys are sorted before emission)
  so PR-comment upserts stay stable.
- **`--fail-on` enforcement** (`none|cve|critical-cve|typosquat|any`).
  Exits with code 2 when the configured threshold trips. The PR comment is
  still posted on a tripped run — the action's `entrypoint.sh` now uses a
  `tee` + `PIPESTATUS` capture instead of `out="$(...)"` so reviewers see
  the findings even when the workflow step fails. `critical-cve` is
  currently aliased to `cve` with a one-shot stderr warning; v0.3 will
  populate per-advisory severity from `/v1/vulns/{id}` and narrow it.
- **Linux aarch64 release artifact**. Built via `cross-rs/cross` so the
  `ring` (transitive `ureq → rustls`) cross-compile from ubuntu-x86_64
  Just Works without per-target CC/AR env-var surgery. Released as
  `bomdrift-vX.Y.Z-aarch64-unknown-linux-gnu.tar.gz` alongside the
  existing three targets, with cosign signature + SHA-256 attached.
- **Multi-ecosystem typosquat detection**. The npm-only enricher now
  covers npm, PyPI, Cargo, and Maven, with rules tuned per-ecosystem:
  - **PyPI**: PEP 503 normalization (`-`/`_`/`.` collapse) on candidate
    and legit-list entries so `scikit_learn` ≡ `scikit-learn`. Embedded
    top-200 list from hugovk/top-pypi-packages.
  - **Cargo**: separator `-` only. Embedded top-200 list from the
    crates.io API (`?sort=downloads`).
  - **Maven**: Levenshtein ≤ 2 on the `artifactId` portion of
    `groupId:artifactId` only — the shared `groupId` prefix would
    inflate Jaro-Winkler past anything useful. ~100 hand-curated
    coordinates from mvnrepository.com Most Popular categories.
- **`bomdrift refresh-typosquat`** now supports `--ecosystem pypi|cargo`
  in addition to `npm`, fetching from each ecosystem's canonical upstream
  with a polite User-Agent and (for Cargo) a 1-second pagination delay.
  `--ecosystem maven` is accepted but emits a notice — Maven Central has
  no canonical "top N" feed. `--ecosystem all` now expands to all four
  (previously expanded to npm only).
- **`verify-signatures` action input** (default `true`). Lets consumers
  on trusted mirrors / cached runners skip the cosign-installer step and
  the .sig/.pem download round-trips (~15s saved). When `true` and cosign
  is missing, the action now fails loudly instead of silently degrading.

### Fixed

- **Wired up `--format`**. v0.1.0 parsed the flag through clap and
  plumbed it through the action via `INPUT_FORMAT`, but `run_diff` never
  read it — every invocation auto-detected via `parse::parse()`. Now
  forces dispatch to the chosen parser when `--format cdx|spdx|syft`
  is supplied; `auto` still auto-detects.
- **Multi-version components no longer silently dropped from diffs**.
  v0.1.0's `BTreeMap<ComponentKey, &Component>` collector kept only the
  last-inserted entry when an SBOM contained the same component at
  multiple versions (legitimate in non-flat dep trees, e.g. npm). The
  diff core now collects `BTreeMap<ComponentKey, Vec<&Component>>` and
  computes pair-by-version per key, surfacing every transition through
  added/removed/license_changed (version_changed remains the
  single-version-per-key fast path for backward-compatible rendering).

### Migration notes

- **`--fail-on`** was a no-op stub in v0.1.0; consumers that set
  `fail-on: cve` and were silently no-op'd will start exiting 2 on CVE
  findings. This is the intended behavior they thought they had — but
  worth checking your workflows before pinning to `@v0.2.0`.
- **Multi-version diff output shape**. Diffs of SBOMs with duplicate
  components at different versions previously emitted one
  `version_changed` pair (silently dropping the others); they now emit
  multiple `added` / `removed` entries. JSON / SARIF / markdown all
  reflect this faithfully.
- **`--ecosystem all`** for `refresh-typosquat` now refreshes four
  ecosystems (npm, PyPI, Cargo, Maven) instead of just npm. Network
  egress increases proportionally; pin to `--ecosystem npm` if you
  need the v0.1.0 behavior.

### Distribution

- Linux aarch64 added to the release matrix. Cosign keyless signatures
  attached to every archive (no change from v0.1.0).
- Release binary still stripped + LTO; ~3.2 MB on Linux x86_64.

## [0.1.0] - 2026-04-28

First public release. The wedge: a single `bomdrift diff before.json after.json`
invocation parses CycloneDX 1.5/1.6, SPDX 2.3, or Syft JSON SBOMs (auto-detected),
diffs them deterministically, and surfaces supply-chain risk signals on every
changed dependency in a format ready to drop into a PR comment.

### Parsers
- CycloneDX 1.5/1.6 JSON
- SPDX 2.3 JSON
- Syft JSON
- Unified component model with cross-format diff keying via purl-without-version
  (falling back to ecosystem+name when no purl is provided)

### Diff
- Categorizes per-component changes into added, removed, version-changed, and
  license-changed (same-version-different-license is the suspicious bucket)
- Byte-deterministic output for stable PR-comment upserts via
  `peter-evans/create-or-update-comment`

### Risk-signal enrichers
- **OSV.dev CVE lookup** via `/v1/querybatch` for added and version-bumped
  components. Best-effort: network failures warn and continue rendering.
- **Typosquat detection** flagging newly added npm components whose name is
  suspiciously close to a top-1000 package, via Jaro-Winkler plus a
  suffix-containment boost rule. Catches the `plain-crypto-js` → `crypto-js`
  pattern that pure JW alone misses. Embedded snapshot of 1000 names sourced
  from anvaka/npmrank; refreshable via `bomdrift refresh-typosquat`.
- **Multi-major version-jump heuristic** flagging dependencies that crossed
  two or more major versions in a single diff (the "takeover swap" / xz
  pattern at SemVer scale). Pure-compute, no I/O, no semver crate.
- **Maintainer-age signal** flagging newly added GitHub-hosted dependencies
  whose top contributor's first commit is younger than 90 days (the xz/Jia
  Tan pattern). Hand-rolled GitHub REST calls via `ureq`; honors
  `GITHUB_TOKEN`; rate-limit-aware. Skipped when the repo has > 50
  contributors. Toggle with `--no-maintainer-age` for offline runs.

### Renderers
- **GitHub-Flavored Markdown** (default for non-TTY / piped output / explicit
  `--output markdown`): summary table plus per-category sections with osv.dev
  hyperlinks, designed for direct posting as a PR comment.
- **Terminal with ANSI color** (default for TTY): tree-style output with
  bracketed `[ADD]`/`[REM]`/`[VER]`/`[LIC]`/`[CVE]`/`[SQT]` prefixes;
  respects `NO_COLOR` and `CLICOLOR_FORCE`.
- **JSON** (`--output json`): pretty-printed `{changes, enrichment}` graph
  for downstream tooling.

### CLI
- `bomdrift diff <before> <after> [--output ...] [--no-osv]
  [--no-maintainer-age] [--format ...]`
- `bomdrift refresh-typosquat [--ecosystem npm|all]` writes refreshed
  popular-package lists to `<XDG_CACHE_HOME>/bomdrift/typosquat/`; the
  enricher prefers cache files over the embedded snapshot when present.

### Distribution

- Pre-built binaries for **Linux x86_64**, **macOS aarch64**, and **Windows
  x86_64**, attached to each GitHub release as `tar.gz` / `zip` archives plus
  SHA-256 checksums. (Linux aarch64 is planned for v0.1.1.)
- **Cosign keyless signatures** (Sigstore via GitHub OIDC) for every released
  archive. Verify with:
  ```bash
  cosign verify-blob \
    --certificate-identity 'https://github.com/Metbcy/bomdrift/.github/workflows/release.yml@refs/tags/v0.1.0' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    --certificate <archive>.pem \
    --signature  <archive>.sig \
    <archive>
  ```
- Release binary stripped + LTO; ~3.2 MB on Linux x86_64.

### GitHub Action

- `Metbcy/bomdrift@v1` (composite, no Docker) downloads the matching release
  archive for the runner's OS+arch, cosign-verifies it (when cosign is
  available), runs `bomdrift diff`, writes the rendered output to the job
  step summary, and upserts the diff as a single PR comment marked
  `<!-- bomdrift:diff -->` so subsequent pushes update the same comment
  instead of accumulating.

### Known gaps (deferred to v0.2)

- `--output sarif` is not implemented (the CLI value is reserved).
- `fail-on=cve|critical-cve|typosquat|any` Action input is accepted for
  forward compatibility but treated as `none` in v0.1.0; the action never
  fails on findings.
- Linux aarch64 binary.
- PyPI / Cargo / Maven typosquat reference lists (only npm in v0.1.0).

[Unreleased]: https://github.com/Metbcy/bomdrift/compare/v0.6.1...HEAD
[0.6.1]: https://github.com/Metbcy/bomdrift/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/Metbcy/bomdrift/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/Metbcy/bomdrift/compare/v0.4.4...v0.5.0
[0.4.4]: https://github.com/Metbcy/bomdrift/releases/tag/v0.4.4
[0.4.3]: https://github.com/Metbcy/bomdrift/releases/tag/v0.4.3
[0.4.2]: https://github.com/Metbcy/bomdrift/releases/tag/v0.4.2
[0.4.1]: https://github.com/Metbcy/bomdrift/releases/tag/v0.4.1
[0.4.0]: https://github.com/Metbcy/bomdrift/releases/tag/v0.4.0
[0.3.0]: https://github.com/Metbcy/bomdrift/releases/tag/v0.3.0
[0.2.0]: https://github.com/Metbcy/bomdrift/releases/tag/v0.2.0
[0.1.0]: https://github.com/Metbcy/bomdrift/releases/tag/v0.1.0
