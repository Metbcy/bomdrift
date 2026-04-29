# bomdrift

> **SBOM diff with supply-chain risk signals.** Flags new CVEs, typosquats, multi-major version jumps, and young-maintainer signals on added or upgraded dependencies — posted as a GitHub PR comment.

[![CI](https://github.com/Metbcy/bomdrift/actions/workflows/ci.yml/badge.svg)](https://github.com/Metbcy/bomdrift/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/Metbcy/bomdrift?sort=semver&display_name=tag)](https://github.com/Metbcy/bomdrift/releases/latest)
[![Docs](https://img.shields.io/badge/docs-mdbook-blue)](https://metbcy.github.io/bomdrift/)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](./LICENSE)

## In 30 seconds

```yaml
# .github/workflows/sbom-diff.yml
on: pull_request
permissions:
  contents: read
  pull-requests: write
jobs:
  diff:
    runs-on: ubuntu-latest
    steps:
      - uses: Metbcy/bomdrift@v1
```

That's it. `Metbcy/bomdrift@v1` runs Syft against your project at the PR base + head, diffs the SBOMs, and posts a single PR comment that updates on every push. See it live on [#1](https://github.com/Metbcy/bomdrift/pull/1) — bomdrift dogfoods itself on its own PRs.

**Quick links:** [Why?](#why-bomdrift) · [vs Socket / Snyk / Trivy](#how-it-compares) · [Action reference](https://metbcy.github.io/bomdrift/github-action.html) · [CLI reference](https://metbcy.github.io/bomdrift/cli-reference.html) · [Suppress findings](https://metbcy.github.io/bomdrift/baseline.html#in-comment-suppression-v05) · [Release signing](#release-signing) · [Examples](./examples/)

## Why bomdrift

The actionable supply-chain question on a pull request is:

> *What changed in this diff's dependencies that I should worry about?*

— not *"what's in my SBOM?"*. Plenty of tools answer the second question. **bomdrift answers the first.**

Recent incidents bomdrift would have surfaced:

- **axios npm compromise (Mar 31, 2026)** — maintainer was socially engineered (fake Slack/Teams call, North Korean UNC1069), and `axios@1.14.1` + `axios@0.30.4` shipped with a malicious runtime dep `plain-crypto-js@4.2.1` that dropped the WAVESHAPER.V2 RAT on Windows/macOS/Linux. Three of bomdrift's signals fire in the diff: a **brand-new transitive dependency** with a **CVE from OSV.dev** (`MAL-2026-2306`), a **typosquat** (`plain-crypto-js` vs the legitimate `crypto-js`, similarity 0.95), and existing CVEs against the upgraded `axios@1.14.1` itself.
- **Shai-Hulud worm (npm, Nov 2025)** — 700+ packages compromised by a self-replicating worm. Diff-time review of newly added transitive deps and version bumps was the only pre-merge defense.
- **xz-utils backdoor (CVE-2024-3094, Mar 2024)** — 2.6-year social-engineering campaign culminating in a backdoor shipped in 5.6.0/5.6.1. The "Jia Tan" maintainer's first commit was recent relative to the release — exactly the maintainer-age heuristic bomdrift implements.
- **Sustained PyPI typosquat campaigns (2024–2026)** — hundreds of malicious packages disguised by single-character substitutions. Jaro-Winkler against top-N catalogs catches these reliably.

## How it compares

|                                          | bomdrift | Socket | Snyk | Trivy |
|------------------------------------------|:---:|:---:|:---:|:---:|
| **Diff-focused** (what *changed*, not what *is*) | yes | yes | partial | no |
| **Open source, no hosted dashboard required** | yes | no | no | yes |
| **Maintainer-age signal (xz pattern)** | yes | partial | no | no |
| **Cosign-signed releases (Sigstore + GitHub OIDC)** | yes | n/a | n/a | no |
| **Single self-contained binary, no Docker** | yes | no | no | yes |
| **In-comment suppression (`/bomdrift suppress`)** | yes | partial | yes | no |
| **No telemetry / no account / no signup** | yes | no | no | yes |
| **SARIF v2.1.0 to GitHub Code Scanning** | yes | no | yes | yes |
| **Eight ecosystems for typosquat detection** | yes | yes | no | no |
| **Apache-2.0** | yes | proprietary | proprietary | yes |

bomdrift fills a specific gap: a free, OSS-first, single-binary tool for the *diff-time* question. It's not a replacement for Snyk's scan-everything posture or Socket's SaaS UX — it's the right answer when you want supply-chain risk signals on PRs without paying for a vendor or running a dashboard.

## Detailed install

### As a GitHub Action (zero-config, v0.5+)

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
      - uses: Metbcy/bomdrift@v1
        # Optional inputs (all have sensible defaults):
        #   fail-on:           critical-cve | cve | typosquat | license-change | any | none
        #   baseline:          .bomdrift/baseline.json
        #   findings-only:     true
        #   verify-signatures: true   (set false on trusted mirrors)
```

Pin to `@v1` for the latest v0.x; pin to `@v0.5.0` for reproducible builds. Run `bomdrift init` if you want a checked-in `.bomdrift.toml` policy and both workflows scaffolded locally. See the [Action reference](https://metbcy.github.io/bomdrift/github-action.html) for every input.

#### Optional: in-comment suppression (v0.5+)

Add a second workflow that watches for `/bomdrift suppress <ID>` comments on PRs:

```yaml
# .github/workflows/bomdrift-suppress.yml
on:
  issue_comment:
    types: [created]
permissions:
  contents: write       # to commit the baseline
  pull-requests: write  # to react on the trigger comment
jobs:
  suppress:
    if: |
      github.event.issue.pull_request &&
      startsWith(github.event.comment.body, '/bomdrift suppress ')
    runs-on: ubuntu-latest
    steps:
      - uses: Metbcy/bomdrift/comment-suppress@v1
```

Comment `/bomdrift suppress GHSA-xxxx` on any PR; the sub-action appends to `.bomdrift/baseline.json` and commits to the PR's branch. The next bomdrift run filters that advisory.

### As a binary (local / CI)

Pre-built binaries cover Linux x86_64 + aarch64, macOS aarch64, and Windows x86_64. Each archive is cosign-signed via Sigstore + GitHub OIDC.

```bash
VERSION=v0.5.0
TARGET=x86_64-unknown-linux-gnu
curl -sSL -o bomdrift.tar.gz \
  "https://github.com/Metbcy/bomdrift/releases/download/${VERSION}/bomdrift-${VERSION}-${TARGET}.tar.gz"
tar -xzf bomdrift.tar.gz
./bomdrift-${VERSION}-${TARGET}/bomdrift --version

# Diff two SBOMs
./bomdrift-${VERSION}-${TARGET}/bomdrift diff before.json after.json
```

Verify the archive's signature before you trust the binary — see [Release signing](#release-signing) below.

### From source

```bash
cargo install --locked --git https://github.com/Metbcy/bomdrift --tag v0.5.0 bomdrift
```

Requires Rust 1.85+ (the project uses edition 2024).

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

# Keep raw churn out of PR comments while preserving risk sections
bomdrift diff before.json after.json --findings-only

# Block unusually large dependency churn
bomdrift diff before.json after.json --max-added 25 --max-version-changed 10

# Suppress findings already present in a baseline snapshot
bomdrift diff before.json after.json --baseline .bomdrift/baseline.json

# Scaffold .bomdrift.toml and GitHub Action workflows
bomdrift init

# Hand-curate a baseline (or let the comment-suppress sub-action do it)
bomdrift baseline add GHSA-xxxx-yyyy-zzzz

# Refresh the bundled popular-package lists (used by the typosquat enricher)
bomdrift refresh-typosquat                     # all ecosystems
bomdrift refresh-typosquat --ecosystem pypi    # one specific list
```

`bomdrift diff` exits 0 on success regardless of findings unless `--fail-on` or a diff budget is set — then it exits 2 when the policy trips. Stdout is Markdown by default when piped/redirected (the PR-comment path) and ANSI-colored when stdout is a TTY. `--output markdown|json|terminal|sarif` overrides detection.

See the [`examples/`](./examples/) directory for end-to-end scenarios (axios incident, multi-ecosystem typosquats, version jumps, baseline suppression).

## Example output

Running `bomdrift diff` against the bundled axios-incident fixture pair produces a comment that summarises the change shape, severity-sorts vulnerabilities, and offers one-click suppression:

```markdown
## SBOM diff

| Change | Count |
|---|---:|
| Added | 1 |
| Removed | 1 |
| Version changed | 1 |
| Possible typosquats | 1 |

<details><summary>Show 1 added — `npm:plain-crypto-js@4.2.1`</summary>

| Ecosystem | Name | Version |
|---|---|---|
| npm | plain-crypto-js | 4.2.1 |
</details>

<details><summary>Show 1 typosquat - `plain-crypto-js` ~= `crypto-js` (0.95)</summary>

| Ecosystem | Name | Similar to | Similarity |
|---|---|---|---:|
| npm | plain-crypto-js | crypto-js | 0.95 |
</details>

---
False positive? Report it · Suppress? Comment `/bomdrift suppress <ID>` · Docs
```

With network access, an additional Vulnerabilities section lists each advisory ID (CVE / GHSA / MAL) per affected component, sorted by OSV.dev-fetched severity (Critical, High, Medium, Low).

## Features

- Diff **CycloneDX 1.5/1.6**, **SPDX 2.3**, and **Syft** JSON SBOMs against each other (any combination), via a unified component model.
- For added & upgraded packages, enrich with **OSV.dev CVE data** through `/v1/querybatch`, then a per-advisory `/v1/vulns/{id}` follow-up to populate **severity** (Critical / High / Medium / Low).
- 24h on-disk **OSV severity cache** (`<XDG_CACHE_HOME>/bomdrift/osv/`) so reruns within a working day don't re-fetch — opt out with `--no-osv-cache`.
- Flag possible **typosquats** across **npm**, **PyPI**, **Cargo**, **Maven**, **Go**, **RubyGems**, **NuGet**, and **Composer** via Jaro-Winkler similarity (Levenshtein for Maven artifactIds), with a suffix-containment boost rule that catches the `plain-crypto-js` to `crypto-js` pattern that pure JW alone misses. Refreshable from each ecosystem's canonical upstream via `bomdrift refresh-typosquat`.
- Flag deps whose **top GitHub maintainer joined the project recently** (the xz-style takeover signal). Honors `GITHUB_TOKEN`, rate-limit-aware, skipped when the repo has > 50 contributors.
- Flag **multi-major version jumps** (≥ 2 majors) in a single diff — often correlates with takeover swaps and namespace reuse.
- **Output formats**: terminal (colored, TTY-aware), Markdown (PR comment, with collapsible sections + severity sort), **JSON**, and **SARIF v2.1.0** for GitHub Code Scanning ingestion.
- **`--fail-on`** thresholds (`cve` / `critical-cve` / `typosquat` / `license-change` / `any`) and diff budgets (`--max-added`, `--max-removed`, `--max-version-changed`) exit code 2 on trip while still emitting the comment body, so the PR comment posts even when the workflow step fails.
- **`.bomdrift.toml` + `bomdrift init`** let repos keep policy in version control instead of repeating inputs in workflow YAML.
- **`/bomdrift suppress <id>`** in-comment suppression (v0.5+) via a companion sub-action.
- **`--baseline <path.json>`** suppresses findings already captured in a previously stored `bomdrift diff --output json` snapshot.
- **`--summary-only`**, **`--findings-only`**, and automatic comment-size fallback (default 60 KB) keep big SBOM diffs under GitHub's 65,536-char comment-body cap.
- Ships as a **single Rust binary** (~3.4 MB, stripped + LTO) **and** a composite GitHub Action — no Docker.
- Releases are **cosign-signed** keyless via Sigstore + GitHub OIDC — eat-your-own-supply-chain-dogfood.

## Release signing

Every release archive is signed with cosign keyless via Sigstore (GitHub OIDC).

```bash
# Replace VERSION + TARGET with your downloaded archive's pair
VERSION=v0.5.0
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
- **[STATUS.md](./STATUS.md)** — known issues and current limitations.

## Contributing

PRs welcome. The `good first issue` label tracks focused asks for new contributors — adding a typosquat name to a top-N list, fixing a doc typo, improving an error message. See [`CONTRIBUTING.md`](./CONTRIBUTING.md) for the dev loop.

## Non-goals

- **SBOM generation.** Use [Syft](https://github.com/anchore/syft) — it's already great. bomdrift only consumes SBOMs (and as of v0.5 invokes Syft itself inside the Action so consumers don't have to).
- **Dependency-tree visualization.** [`cargo tree`](https://doc.rust-lang.org/cargo/commands/cargo-tree.html), [`pnpm why`](https://pnpm.io/cli/why), and friends do this well.
- **Replacing your SCA scanner.** OSV-scanner, Grype, Trivy all have richer vulnerability databases. bomdrift's CVE enrichment is *change-focused*: only on what's new in this diff.

## License

Apache-2.0 — see [LICENSE](./LICENSE).
