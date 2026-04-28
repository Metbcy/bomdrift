# bomdrift

> SBOM diff with supply-chain risk signals — flags **new CVEs**, **typosquats**, **multi-major version jumps**, and **young maintainers** on added or upgraded dependencies, surfaced as a GitHub PR comment.

[![CI](https://github.com/Metbcy/bomdrift/actions/workflows/ci.yml/badge.svg)](https://github.com/Metbcy/bomdrift/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](./LICENSE)

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
```

### As a binary (local / CI)

Download a signed release archive for your platform from the [Releases page](https://github.com/Metbcy/bomdrift/releases/latest) and verify it with cosign — see [Release signing](#release-signing) below.

```bash
# Linux x86_64 example
curl -sSL -o bomdrift.tar.gz https://github.com/Metbcy/bomdrift/releases/latest/download/bomdrift-v0.1.0-x86_64-unknown-linux-gnu.tar.gz
tar -xzf bomdrift.tar.gz
./bomdrift-v0.1.0-x86_64-unknown-linux-gnu/bomdrift --version
```

### From source

```bash
cargo install --locked --git https://github.com/Metbcy/bomdrift --tag v0.1.0 bomdrift
```

## Usage

```bash
# Diff two SBOMs (auto-detects CycloneDX / SPDX / Syft)
bomdrift diff before.json after.json

# Offline mode (no OSV / no GitHub-API maintainer-age lookups)
bomdrift diff before.json after.json --no-osv --no-maintainer-age

# Machine-readable JSON for downstream tooling
bomdrift diff before.json after.json --output json

# Refresh the bundled npm popular-package list (used by the typosquat enricher)
bomdrift refresh-typosquat --ecosystem npm
```

`bomdrift diff` exits 0 on success regardless of findings. It emits Markdown by default when stdout is piped/redirected (the PR-comment path), and ANSI-colored terminal output when stdout is a TTY. `--output markdown|json|terminal` overrides detection.

## Features

- Diff **CycloneDX 1.5/1.6**, **SPDX 2.3**, and **Syft** JSON SBOMs against each other (any combination), via a unified component model.
- For added & upgraded packages, enrich with **OSV.dev CVE data** through the `/v1/querybatch` endpoint.
- Flag possible **typosquats** via Jaro-Winkler similarity to top-1000 npm packages, with a suffix-containment boost rule that catches the `plain-crypto-js` → `crypto-js` pattern that pure JW alone misses.
- Flag deps whose **top GitHub maintainer joined the project recently** (the xz-style takeover signal). Honors `GITHUB_TOKEN`, rate-limit-aware, skipped when the repo has > 50 contributors.
- Flag **multi-major version jumps** (≥ 2 majors) in a single diff — often correlates with takeover swaps and namespace reuse.
- Output formats: terminal (colored, TTY-aware), Markdown (PR comment), JSON. SARIF planned for v0.2.
- Ships as a single Rust binary **and** a composite GitHub Action — no Docker.
- Releases are signed with [cosign keyless](https://docs.sigstore.dev/) — eat-your-own-supply-chain-dogfood.

## Release signing

Every release archive is signed with cosign keyless via Sigstore (GitHub OIDC).

```bash
cosign verify-blob \
  --certificate-identity 'https://github.com/Metbcy/bomdrift/.github/workflows/release.yml@refs/tags/v0.1.0' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate bomdrift-v0.1.0-x86_64-unknown-linux-gnu.tar.gz.pem \
  --signature  bomdrift-v0.1.0-x86_64-unknown-linux-gnu.tar.gz.sig \
  bomdrift-v0.1.0-x86_64-unknown-linux-gnu.tar.gz
```

The Action verifies signatures automatically when cosign is available on the runner.

## Non-goals

- **SBOM generation.** Use [Syft](https://github.com/anchore/syft) — it's already great. bomdrift only consumes SBOMs.
- **Dependency-tree visualization.** [`cargo tree`](https://doc.rust-lang.org/cargo/commands/cargo-tree.html), [`pnpm why`](https://pnpm.io/cli/why), and friends do this well.
- **Replacing your SCA scanner.** OSV-scanner, Grype, Trivy all have richer vulnerability databases. bomdrift's CVE enrichment is *change-focused*: only on what's new in this diff.

## License

Apache-2.0 — see [LICENSE](./LICENSE).
