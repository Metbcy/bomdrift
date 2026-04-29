# bomdrift

> SBOM diff with supply-chain risk signals — flags **new CVEs**, **typosquats**, **multi-major version jumps**, and **young maintainers** on added or upgraded dependencies, surfaced as a GitHub PR comment.

[![CI](https://github.com/Metbcy/bomdrift/actions/workflows/ci.yml/badge.svg)](https://github.com/Metbcy/bomdrift/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/Metbcy/bomdrift?sort=semver&display_name=tag)](https://github.com/Metbcy/bomdrift/releases/latest)
[![Docs](https://img.shields.io/badge/docs-mdbook-blue)](https://metbcy.github.io/bomdrift/)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](./LICENSE)

**Quick links:** [Why?](#why) · [Install](#install) · [Usage](#usage) · [Example output](#example-output) · [Features](#features) · [Release signing](#release-signing) · [Docs site](https://metbcy.github.io/bomdrift/) · [Examples](./examples/)

## Why?

The most actionable supply-chain question on a pull request is:

> *What changed in this diff's dependencies that I should worry about?*

— not *"what's in my SBOM?"*. Plenty of tools answer the second question. **bomdrift answers the first.**

Recent incidents bomdrift would have surfaced:

- **axios npm compromise (Mar 31, 2026)** — maintainer was socially engineered (fake Slack/Teams call, North Korean UNC1069), and `axios@1.14.1` + `axios@0.30.4` shipped with a malicious runtime dep `plain-crypto-js@4.2.1` that dropped the WAVESHAPER.V2 RAT on Windows/macOS/Linux. Three of bomdrift's signals fire in the diff: a **brand-new transitive dependency** with a **CVE from OSV.dev** (`MAL-2026-2306`), a **typosquat** (`plain-crypto-js` vs the legitimate `crypto-js`, similarity 0.95), and existing CVEs against the upgraded `axios@1.14.1` itself.
- **Shai-Hulud worm (npm, Nov 2025)** — 700+ packages compromised by a self-replicating worm. Diff-time review of newly added transitive deps and version bumps was the only pre-merge defense.
- **xz-utils backdoor (CVE-2024-3094, Mar 2024)** — 2.6-year social-engineering campaign culminating in a backdoor shipped in 5.6.0/5.6.1. The "Jia Tan" maintainer's first commit was recent relative to the release — exactly the maintainer-age heuristic bomdrift implements.
- **Sustained PyPI typosquat campaigns (2024–2026)** — hundreds of malicious packages disguised by single-character substitutions. Jaro-Winkler against top-N catalogs catches these reliably.

## Install

### As a GitHub Action

```yaml
# .github/workflows/sbom-diff.yml
name: SBOM diff
on: pull_request
permissions:
  contents: read
  pull-requests: write       # to upsert the diff comment
jobs:
  diff:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: anchore/sbom-action@v0
        with: { path: ., output-file: after.json }
      - uses: actions/checkout@v4
        with: { ref: ${{ github.event.pull_request.base.ref }}, path: base }
      - uses: anchore/sbom-action@v0
        with: { path: base, output-file: before.json }
      - uses: Metbcy/bomdrift@v1
        with:
          before-sbom: before.json
          after-sbom:  after.json
          fail-on:     critical-cve   # optional: exit 2 on HIGH/CRITICAL advisories
```

The `@v1` mutable tag tracks the latest v0.x release; pin to a specific version (`@v0.3.0`) if you prefer reproducible builds. See the [Action reference](https://metbcy.github.io/bomdrift/github-action.html) for every input.

### As a binary (local / CI)

Download a signed release archive for your platform from the [Releases page](https://github.com/Metbcy/bomdrift/releases/latest) and verify it with cosign — see [Release signing](#release-signing) below. Pre-built binaries cover **Linux x86_64 + aarch64**, **macOS aarch64**, and **Windows x86_64**.

```bash
# Linux x86_64 example (replace VERSION/TARGET as needed)
VERSION=v0.3.0
TARGET=x86_64-unknown-linux-gnu
curl -sSL -o bomdrift.tar.gz \
  "https://github.com/Metbcy/bomdrift/releases/download/${VERSION}/bomdrift-${VERSION}-${TARGET}.tar.gz"
tar -xzf bomdrift.tar.gz
./bomdrift-${VERSION}-${TARGET}/bomdrift --version
```

### From source

```bash
cargo install --locked --git https://github.com/Metbcy/bomdrift --tag v0.3.0 bomdrift
```

## Usage

```bash
# Diff two SBOMs (auto-detects CycloneDX / SPDX / Syft)
bomdrift diff before.json after.json

# Offline mode (no OSV / no GitHub-API maintainer-age lookups)
bomdrift diff before.json after.json --no-osv --no-maintainer-age

# Machine-readable formats for downstream tooling
bomdrift diff before.json after.json --output json
bomdrift diff before.json after.json --output sarif

# Exit 2 on findings (the action wraps this for PR-comment workflows)
bomdrift diff before.json after.json --fail-on critical-cve

# Suppress findings already present in a baseline snapshot
bomdrift diff before.json after.json --baseline previous-diff.json

# Refresh the bundled popular-package lists (used by the typosquat enricher)
bomdrift refresh-typosquat                     # all ecosystems
bomdrift refresh-typosquat --ecosystem pypi    # one specific list
```

`bomdrift diff` exits 0 on success regardless of findings unless `--fail-on` is set — then it exits 2 when the threshold trips. Stdout is Markdown by default when piped/redirected (the PR-comment path) and ANSI-colored when stdout is a TTY. `--output markdown|json|terminal|sarif` overrides detection.

See the [`examples/`](./examples/) directory for end-to-end scenarios (axios incident, multi-ecosystem typosquats, version jumps, baseline suppression).

## Example output

Running `bomdrift diff` against the bundled axios-incident fixture pair (`tests/fixtures/cdx-minimal.json` → `tests/fixtures/cdx-after.json`) produces:

```markdown
## SBOM diff

| Change | Count |
|---|---:|
| Added | 1 |
| Removed | 1 |
| Version changed | 1 |
| License changed | 0 |
| Possible typosquats | 1 |

### Added
| Ecosystem | Name | Version |
|---|---|---|
| npm | plain-crypto-js | 4.2.1 |

### Version changed
| Ecosystem | Name | Before | After |
|---|---|---|---|
| npm | axios | 1.14.0 | 1.14.1 |

### Possible typosquats
| Ecosystem | Name | Version | Similar to | Similarity |
|---|---|---|---|---:|
| npm | plain-crypto-js | 4.2.1 | crypto-js | 0.95 |
```

With network access, the **Vulnerabilities** section additionally lists each advisory ID (CVE / GHSA / MAL) per affected component, alongside its OSV.dev-sourced severity.

## Features

- Diff **CycloneDX 1.5/1.6**, **SPDX 2.3**, and **Syft** JSON SBOMs against each other (any combination), via a unified component model.
- For added & upgraded packages, enrich with **OSV.dev CVE data** through `/v1/querybatch`, then a per-advisory `/v1/vulns/{id}` follow-up to populate **severity** (Critical / High / Medium / Low).
- 24h on-disk **OSV severity cache** (`<XDG_CACHE_HOME>/bomdrift/osv/`) so reruns within a working day don't re-fetch — opt out with `--no-osv-cache`.
- Flag possible **typosquats** across **npm**, **PyPI**, **Cargo**, and **Maven** via Jaro-Winkler similarity (Levenshtein for Maven artifactIds), with a suffix-containment boost rule that catches the `plain-crypto-js` → `crypto-js` pattern that pure JW alone misses. Refreshable from each ecosystem's canonical upstream via `bomdrift refresh-typosquat`.
- Flag deps whose **top GitHub maintainer joined the project recently** (the xz-style takeover signal). Honors `GITHUB_TOKEN`, rate-limit-aware, skipped when the repo has > 50 contributors.
- Flag **multi-major version jumps** (≥ 2 majors) in a single diff — often correlates with takeover swaps and namespace reuse.
- **Output formats**: terminal (colored, TTY-aware), Markdown (PR comment), **JSON**, and **SARIF v2.1.0** for GitHub Code Scanning ingestion.
- **`--fail-on`** thresholds (`cve` / `critical-cve` / `typosquat` / `any`) exit code 2 on trip while still emitting the comment body, so the PR comment posts even when the workflow step fails.
- **`--baseline <path.json>`** suppresses findings already captured in a previously stored `bomdrift diff --output json` snapshot — adopt bomdrift on a project with pre-existing findings without drowning the first PR.
- **`--summary-only`** + automatic comment-size fallback (default 60 KB) keeps big SBOM diffs under GitHub's 65,536-char comment-body cap.
- Ships as a **single Rust binary** (~3.4 MB, stripped + LTO) **and** a composite GitHub Action — no Docker.
- Releases are **cosign-signed** keyless via Sigstore + GitHub OIDC — eat-your-own-supply-chain-dogfood.

## Release signing

Every release archive is signed with cosign keyless via Sigstore (GitHub OIDC).

```bash
# Replace VERSION + TARGET with your downloaded archive's pair
VERSION=v0.3.0
TARGET=x86_64-unknown-linux-gnu
ARCHIVE=bomdrift-${VERSION}-${TARGET}.tar.gz

cosign verify-blob \
  --certificate-identity "https://github.com/Metbcy/bomdrift/.github/workflows/release.yml@refs/tags/${VERSION}" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate "${ARCHIVE}.pem" \
  --signature  "${ARCHIVE}.sig" \
  "${ARCHIVE}"
```

The Action verifies signatures automatically by default. Set `verify-signatures: false` on trusted mirrors to skip the cosign install step (~15s saved per run).

## Documentation

- **[Docs site (mdBook)](https://metbcy.github.io/bomdrift/)** — full reference: CLI flags, every action input, output-format anatomy, per-enricher deep dives, architecture notes, roadmap.
- **[`examples/`](./examples/)** — runnable scenarios with synthetic SBOM pairs.
- **[CHANGELOG](./CHANGELOG.md)** — release notes per version, including breaking-change migration notes.

## Non-goals

- **SBOM generation.** Use [Syft](https://github.com/anchore/syft) — it's already great. bomdrift only consumes SBOMs.
- **Dependency-tree visualization.** [`cargo tree`](https://doc.rust-lang.org/cargo/commands/cargo-tree.html), [`pnpm why`](https://pnpm.io/cli/why), and friends do this well.
- **Replacing your SCA scanner.** OSV-scanner, Grype, Trivy all have richer vulnerability databases. bomdrift's CVE enrichment is *change-focused*: only on what's new in this diff.

## License

Apache-2.0 — see [LICENSE](./LICENSE).
