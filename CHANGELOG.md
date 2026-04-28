# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/Metbcy/bomdrift/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Metbcy/bomdrift/releases/tag/v0.1.0
