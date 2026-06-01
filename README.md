# bomdrift

> **SBOM diff with supply-chain risk signals.** Flags new CVEs (with EPSS + CISA KEV signal), typosquats across 8 ecosystems, multi-major version jumps, young-maintainer takeovers, recently-published / deprecated / maintainer-set-changed registry signals, and license-policy violations on every changed dependency — posted as a comment on GitHub, GitLab, Bitbucket, or Azure DevOps PRs.

[![CI](https://github.com/Metbcy/bomdrift/actions/workflows/ci.yml/badge.svg)](https://github.com/Metbcy/bomdrift/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/bomdrift.svg)](https://crates.io/crates/bomdrift)
[![docs.rs](https://img.shields.io/docsrs/bomdrift)](https://docs.rs/bomdrift)
[![GitHub Marketplace](https://img.shields.io/badge/marketplace-bomdrift-blue?logo=github)](https://github.com/marketplace/actions/bomdrift)
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

**Quick links:** [Why?](#why-bomdrift) · [vs Socket / Snyk / Trivy / OSV-Scanner / Grype](#how-it-compares) · [Action reference](https://metbcy.github.io/bomdrift/github-action.html) · [CLI reference](https://metbcy.github.io/bomdrift/cli-reference.html) · [License policy](https://metbcy.github.io/bomdrift/license-policy.html) · [VEX](https://metbcy.github.io/bomdrift/vex.html) · [SARIF](https://metbcy.github.io/bomdrift/sarif.html) · [OCI attestation](https://metbcy.github.io/bomdrift/attestation.html) · [Plugins](https://metbcy.github.io/bomdrift/plugins.html) · [GitLab](https://metbcy.github.io/bomdrift/gitlab-ci.html) · [Bitbucket](https://metbcy.github.io/bomdrift/bitbucket.html) · [Azure DevOps](https://metbcy.github.io/bomdrift/azure-devops.html) · [Suppress findings](https://metbcy.github.io/bomdrift/baseline.html#in-comment-suppression-v05) · [Release signing](#release-signing) · [Examples](./examples/)

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

The dimensions adopters actually filter on. Correct as of v0.9.9.

|                                          | bomdrift | Socket | Snyk | Trivy | OSV-Scanner | Grype |
|------------------------------------------|:---:|:---:|:---:|:---:|:---:|:---:|
| **Diff-focused** (what *changed*, not what *is*) | yes | yes | partial | no | no | no |
| **Open source, no hosted dashboard required** | yes | no | no | yes | yes | yes |
| **Maintainer-age signal (xz pattern)** | yes | partial | no | no | no | no |
| **Multi-SCM PR comments** (GitHub / GitLab / Bitbucket / Azure DevOps) | yes (all four, v0.9.5+) | GitHub mainly | GitHub + GitLab | no | no | no |
| **In-comment suppression** (`/bomdrift suppress`) | yes (all four SCMs) | partial | yes | no | no | no |
| **License policy with SPDX expression evaluation + per-exception allow/deny** | yes (v0.9.5) | no | partial | no | no | no |
| **VEX consume + emit** (OpenVEX 0.2.0 + CycloneDX VEX 1.6) | yes (v0.9) | no | partial | partial (consume) | no | no |
| **OCI attestation verification** (`cosign verify-attestation`) | yes (v0.9.6) | no | no | partial | no | no |
| **External-process plugin system** (custom rules) | yes (v0.9.6) | no | partial | no | no | no |
| **SARIF v2.1.0 → GitHub Code Scanning** | yes (v0.8) | no | yes | yes | yes | yes |
| **Eight-ecosystem typosquat detection** (npm/PyPI/Cargo/Maven/Go/Gem/NuGet/Composer) | yes | yes | no | no | no | no |
| **EPSS + CISA KEV signals** | yes (v0.8) | partial | yes | no | partial | no |
| **Cosign-signed releases (Sigstore + GitHub OIDC)** | yes | n/a | n/a | no | yes | yes |
| **Byte-deterministic output** (SOURCE_DATE_EPOCH-honored) | yes | n/a | no | no | no | no |
| **Single self-contained binary, no Docker** | yes | no | no | yes | yes | yes |
| **No telemetry / no account / no signup** | yes | no | no | yes | yes | yes |
| **Auto-fix PR generation** | **no** (pair with Renovate / Dependabot) | no | yes | no | no | no |
| **Reachability / call-graph analysis** | **no** (pair with Endor / Snyk Reachability) | partial | yes | no | no | no |
| **License** | Apache-2.0 | proprietary | proprietary | Apache-2.0 | Apache-2.0 | Apache-2.0 |

bomdrift fills a specific gap: a free, OSS-first, single-binary tool for the *diff-time* question. It's not a replacement for Snyk's scan-everything posture or Socket's SaaS UX — it's the right answer when you want supply-chain risk signals on PRs without paying for a vendor or running a dashboard. For reachability and tarball-behavior analysis, pair bomdrift with the tools called out in the [Pair with…](#pair-with) table.

For a per-incident walk-through of which bomdrift signals would have fired (and which would not) on five published supply-chain incidents — xz-utils, event-stream, ua-parser-js, colors.js, node-ipc — see [**What bomdrift catches that others miss**](https://metbcy.github.io/bomdrift/comparison.html).

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

Pin to `@v1` for the latest v0.x; pin to `@v0.9.9` for reproducible builds. Run `bomdrift init` if you want a checked-in `.bomdrift.toml` policy and both workflows scaffolded locally. See the [Action reference](https://metbcy.github.io/bomdrift/github-action.html) for every input — including `upload-to-code-scanning`, `verify-signatures`, `comment-size-limit`, and the `before-sbom`/`after-sbom` escape hatch.

**Other forges:** GitLab CI, Bitbucket Pipelines, and Azure DevOps Pipelines all have ready-to-copy templates under [`examples/`](./examples/) and dedicated docs chapters: [GitLab CI](https://metbcy.github.io/bomdrift/gitlab-ci.html), [Bitbucket](https://metbcy.github.io/bomdrift/bitbucket.html), [Azure DevOps](https://metbcy.github.io/bomdrift/azure-devops.html). Comment-driven `/bomdrift suppress` works on all four SCMs via the Cloudflare Worker bridges added in v0.9.5.

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

Pre-built binaries cover Linux x86_64 + aarch64, macOS aarch64, and Windows x86_64. Each archive is cosign-signed via Sigstore + GitHub OIDC, and (v0.9.9+) carries a SLSA build provenance attestation.

**Install via `cargo` (v0.9.9+):**

```bash
cargo install --locked bomdrift
bomdrift --version
```

**Install via Docker / OCI (v0.9.9+):**

```bash
docker run --rm ghcr.io/metbcy/bomdrift:latest --version
# Pin to a specific version for reproducible CI:
docker run --rm ghcr.io/metbcy/bomdrift:v0.9.9 --version
```

The image is multi-arch (`linux/amd64`, `linux/arm64`), distroless, runs as a non-root user, and ships with an inline SLSA attestation (verify with `gh attestation verify --owner Metbcy oci://ghcr.io/metbcy/bomdrift:v0.9.9`).

**Install from a release archive:**

```bash
VERSION=v0.9.9
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
cargo install --locked --git https://github.com/Metbcy/bomdrift --tag v0.9.9 bomdrift
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

### SBOM ingest

- Diff **CycloneDX 1.5/1.6**, **SPDX 2.3**, and **Syft JSON** against each other (any combination), via a unified component model.
- Optional **`--before-attestation` / `--after-attestation`**: fetch the SBOM from an OCI registry as a `cosign verify-attestation`-verified artifact instead of a local file (v0.9.6). See [OCI attestation](https://metbcy.github.io/bomdrift/attestation.html).

### Risk-signal enrichers

- **OSV.dev CVE lookup** via `/v1/querybatch` + per-advisory `/v1/vulns/{id}` for severity (Critical / High / Medium / Low). On-disk severity cache, configurable TTL via `--cache-ttl-hours` (v0.9.6).
- **EPSS** (FIRST.org Exploit Prediction Scoring System) per CVE, with `--fail-on-epss <0.0–1.0>` threshold gating (v0.8).
- **CISA KEV** known-exploited flag per advisory, with `--fail-on kev` gating (v0.8).
- **Typosquat detection** across **npm**, **PyPI**, **Cargo**, **Maven**, **Go**, **RubyGems**, **NuGet**, and **Composer**. Jaro-Winkler + suffix-containment boost (Levenshtein for Maven artifactIds, last-path-segment match for Go, package-portion match for Composer). Threshold tunable via `--typosquat-similarity-threshold` (v0.9.6). Refreshable via `bomdrift refresh-typosquat`.
- **Maintainer-age signal** — top contributor's first commit younger than `--young-maintainer-days` (default 90; tunable v0.9.6). The xz / Jia Tan pattern. Covers GitHub (`GITHUB_TOKEN`), GitLab (`GITLAB_TOKEN`), and Codeberg (`CODEBERG_TOKEN`). Skipped on repos with > 50 contributors.
- **Multi-major version jumps** (≥ 2 majors) — pure compute, correlates with takeover swaps and namespace reuse.
- **Registry-metadata enrichers (npm / PyPI / crates.io)** — recently-published, deprecated, maintainer-set-changed (npm-only) (v0.9). Threshold via `--recently-published-days`, opt-out via `--no-registry`.
- **License policy** — `--allow-licenses` / `--deny-licenses` with SPDX expression evaluation (v0.9), plus per-exception `--allow-exception` / `--deny-exception` for `WITH`-clause granularity (v0.9.5).

### Suppression

- **`--baseline <path.json>`** — JSON snapshot suppression with conservative per-purl-and-version match keys.
- **`/bomdrift suppress <ID> [reason: …]`** in-comment workflow on **all four SCMs**: GitHub (v0.5), GitLab (v0.9 via Cloudflare Worker), Bitbucket Cloud (v0.9.5), Azure DevOps (v0.9.5).
- **Time-boxed suppressions** with `expires` + `reason` fields per baseline entry (v0.8). Expired entries warn and surface; never silently keep suppressing.
- **VEX consume / emit** — OpenVEX 0.2.0 + CycloneDX VEX 1.6 on input (`--vex <path>`, repeatable); OpenVEX 0.2.0 on output (`--emit-vex <path>`) (v0.9). See [VEX](https://metbcy.github.io/bomdrift/vex.html).

### Output

- Terminal (TTY-aware ANSI), Markdown (PR comment, severity-sorted), JSON, and **SARIF v2.1.0** with stable rule IDs + `partialFingerprints.primaryHash/v1` for Code Scanning ingestion (v0.8). See [SARIF](https://metbcy.github.io/bomdrift/sarif.html).
- `--output-file <path>` writes to a file instead of stdout (v0.8) — useful for `--output sarif` in YAML pipelines where `>` redirection is fragile.
- **Byte-deterministic** — identical inputs produce byte-identical output, honoring `SOURCE_DATE_EPOCH`. PR-comment upserts patch in place rather than accumulating duplicates.

### Failure thresholds

- `--fail-on` (`cve` / `critical-cve` / `typosquat` / `license-change` / `any` / `kev`) and `--fail-on-epss <N>`. Diff budgets (`--max-added`, `--max-removed`, `--max-version-changed`). All emit the comment body before the exit-2 trip so reviewers see findings even on failed runs.

### Forge integration

- `--platform <github|gitlab|bitbucket|azure-devops>` controls comment-footer shape; auto-detects from `GITLAB_CI` / `BITBUCKET_BUILD_NUMBER` / `TF_BUILD` env vars.
- Composite GitHub Action with `upload-to-code-scanning`, `verify-signatures`, `comment-size-limit` inputs.
- Per-SCM Cloudflare Worker bridges under `examples/<scm>/comment-bridge/` (v0.9 / v0.9.5).

### Extensibility

- **External-process plugin system** via `--plugin <manifest.toml>` (repeatable). JSON over stdin/stdout, fail-soft. See [Plugins](https://metbcy.github.io/bomdrift/plugins.html) and the worked example at [`examples/plugins/banned-packages/`](./examples/plugins/banned-packages/) (v0.9.6).

### Packaging

- Single Rust binary (~3.4 MB stripped + LTO) **and** a composite GitHub Action — no Docker.
- Releases are **cosign-signed** keyless via Sigstore + GitHub OIDC.
- `.bomdrift.toml` + `bomdrift init` keep policy in version control rather than repeating inputs in YAML.

## Release signing

Every release archive is signed with cosign keyless via Sigstore (GitHub OIDC).

```bash
# Replace VERSION + TARGET with your downloaded archive's pair
VERSION=v0.9.9
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

### Continuous fuzzing (v0.9.8+)

The CycloneDX, SPDX, and Syft JSON parsers are continuously fuzzed
via [`cargo-fuzz`](https://rust-fuzz.github.io/book/cargo-fuzz/).
Pull requests touching `src/parse/**` get a short fuzz pass per
target on Linux nightly; a longer scheduled run executes weekly on
`main`. Crash artifacts are uploaded for triage.
See [`.github/workflows/fuzz.yml`](./.github/workflows/fuzz.yml) and
[`fuzz/fuzz_targets/`](./fuzz/fuzz_targets/).

## Documentation

- **[Docs site (mdBook)](https://metbcy.github.io/bomdrift/)** — full reference: CLI flags, every action input, output-format anatomy, per-enricher deep dives, architecture notes, roadmap.
- **[`examples/`](./examples/)** — runnable scenarios with synthetic SBOM pairs.
- **[CHANGELOG](./CHANGELOG.md)** — release notes per version, including breaking-change migration notes.
- **[STATUS.md](./STATUS.md)** — known issues and current limitations.

## Contributing

PRs welcome. The `good first issue` label tracks focused asks for new contributors — adding a typosquat name to a top-N list, fixing a doc typo, improving an error message. See [`CONTRIBUTING.md`](./CONTRIBUTING.md) for the dev loop.

## Non-goals

bomdrift's design constraints (OSS-first, single-binary, no
telemetry, change-focused) put a number of capabilities deliberately
out of scope. We don't ship them, but we recommend pairing bomdrift
with tools that do. See [STATUS.md](./STATUS.md) and the
[roadmap](https://metbcy.github.io/bomdrift/roadmap.html) for the
canonical, version-controlled list.

- **SBOM generation.** Use [Syft](https://github.com/anchore/syft) —
  it's already great. bomdrift only consumes SBOMs (and as of v0.5
  invokes Syft itself inside the Action so consumers don't have to).
- **Replacing your SCA scanner.** OSV-scanner, Grype, Trivy all
  have richer vulnerability databases for *full-tree* scans.
  bomdrift's CVE enrichment is **change-focused**: only on what's
  new in this diff.
- **Dependency-tree visualization.**
  [`cargo tree`](https://doc.rust-lang.org/cargo/commands/cargo-tree.html),
  [`pnpm why`](https://pnpm.io/cli/why), and friends do this well.
- **Per-language deep parsing** (resolving lockfile edge cases beyond
  what Syft already handles). bomdrift consumes whatever the
  upstream SBOM generator produces.
- **Web UI / dashboard.** bomdrift output is markdown / SARIF / JSON
  for ingestion by tooling you already have (PR comments, Code
  Scanning, your own scripts). No daemon, no hosted UI.
- **Reachability / call-graph analysis.** "Is this CVE reachable
  from my code's entry points?" requires AST + call-graph
  infrastructure orthogonal to SBOM diffing. *Pair with Endor Labs
  or Snyk Reachability.*
- **Static analysis of registry tarballs.** Detecting malicious code
  inside a published package needs a sandbox + behavior heuristics.
  *Pair with [Socket](https://socket.dev/).*
- **Auto-fix PR generation.** bomdrift surfaces findings; it doesn't
  open follow-up PRs. *Pair with Renovate or Dependabot.*
- **Container / OCI image scanning.** SBOM + image-layer scanning is
  Trivy / Grype's lane. Use them; bomdrift focuses on
  application-dependency drift between two SBOMs.
- **SAST / secrets scanning.** Different problem space; well
  served by GitHub Advanced Security, Semgrep, or gitleaks.
- **Risk-score dashboards / asset-context aggregation.** Cross-repo
  dashboards inevitably require telemetry, which violates bomdrift's
  no-telemetry tenet. *Pair with Endor / Snyk if your org needs
  centralized risk reporting.*
- **Continuous monitoring / always-on agent.** bomdrift is a
  one-shot CLI invoked from CI. There's no daemon, no telemetry, no
  scheduled background polling. *Run bomdrift in a scheduled CI
  workflow if you want periodic re-checks.*
- **Closed-source advisory databases.** bomdrift uses OSV.dev (the
  open advisory aggregator). Closed proprietary feeds aren't
  consumed in the OSS distribution.

### Pair with…

| Need | Recommended tool |
|---|---|
| Reachability analysis | Endor Labs, Snyk Reachability |
| Tarball / behavior analysis | Socket |
| Auto-fix PRs | Renovate, Dependabot |
| Container image scans | Trivy, Grype |
| SAST / secrets | GitHub Advanced Security, Semgrep, gitleaks |
| Cross-repo risk dashboards | Endor, Snyk |
| SBOM generation | Syft (bomdrift bundles this in the Action) |

## License

Apache-2.0 — see [LICENSE](./LICENSE).
