# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/Metbcy/bomdrift/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/Metbcy/bomdrift/releases/tag/v0.2.0
[0.1.0]: https://github.com/Metbcy/bomdrift/releases/tag/v0.1.0
