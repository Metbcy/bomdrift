# Introduction

**bomdrift** is a CLI and multi-SCM action that diffs two SBOMs and surfaces
supply-chain risk signals on every changed dependency — flags **new CVEs**
(with EPSS + CISA KEV scoring), **typosquats** across eight ecosystems,
**multi-major version jumps**, **young-maintainer takeovers**,
**registry-metadata signals** (recently-published, deprecated,
maintainer-set-changed), and **license-policy violations** — ready to drop
into a PR comment on **GitHub**, **GitLab**, **Bitbucket**, or
**Azure DevOps**.

## What problem does it solve?

The most actionable supply-chain question on a pull request is:

> *What changed in this diff's dependencies that I should worry about?*

— not *"what's in my SBOM?"*. Plenty of tools answer the second question
(OSV-scanner, Grype, Trivy). bomdrift answers the first.

## Recent incidents bomdrift would have surfaced

### axios npm compromise (Mar 31, 2026)

A maintainer was socially engineered (fake Slack/Teams call attributed to
North Korean UNC1069), and `axios@1.14.1` + `axios@0.30.4` shipped briefly
with a malicious runtime dep `plain-crypto-js@4.2.1` that dropped the
WAVESHAPER.V2 RAT on Windows, macOS, and Linux.

Three of bomdrift's signals would have fired in the diff that pulled the
compromised release:

1. **Added** — a brand-new transitive dependency `plain-crypto-js@4.2.1`
   appears.
2. **Typosquat** — `plain-crypto-js` scores 0.95 against the legitimate
   `crypto-js` via the suffix-containment boost rule.
3. **Vulnerabilities** — OSV.dev returns the published advisory IDs
   (`MAL-2026-2306`, `GHSA-3p68-rc4w-qgx5`, etc.) on both versions, with
   EPSS / KEV badges where applicable.

See [`examples/axios-incident/`](https://github.com/Metbcy/bomdrift/tree/main/examples/axios-incident)
for the SBOM pair and the rendered output.

### Shai-Hulud worm (npm, Nov 2025)

700+ packages compromised by a self-replicating worm. Diff-time review of
newly added transitive deps and version bumps was the only pre-merge
defense. bomdrift's "added components + CVE enrichment + recently-
published registry signal" combination surfaces this class of attack at
PR time.

### xz-utils backdoor (CVE-2024-3094, Mar 2024)

A 2.6-year social-engineering campaign culminating in a backdoor shipped
in xz 5.6.0/5.6.1. The "Jia Tan" maintainer's first commit was recent
relative to the release — exactly the maintainer-age heuristic bomdrift
implements via the GitHub REST API. The threshold is tunable via
`--young-maintainer-days` (default 90; v0.9.6+).

### Sustained PyPI typosquat campaigns (2024–2026)

Hundreds of malicious packages disguised by single-character substitutions.
Jaro-Winkler similarity against top-N catalogs catches these reliably; see
the [Typosquat detection](./enrichers/typosquat.md) chapter for the full
algorithm and the `--typosquat-similarity-threshold` knob (v0.9.6+).

## Design ethos

- **Small dep tree, no Docker, single binary.** ~3.4 MB stripped + LTO.
  No tokio, no chrono, no semver crate, no octocrab — the constraint is
  load-bearing.
- **Best-effort enrichers.** Network failures (OSV, EPSS, KEV, GitHub,
  registries), plugin failures, and attestation-verify failures all
  warn-and-continue. A PR review is still useful without one signal,
  and the offline change-shape signals always work.
- **Byte-deterministic output.** Identical inputs render to byte-identical
  Markdown / JSON / SARIF / VEX every time, honoring `SOURCE_DATE_EPOCH`,
  so PR-comment upserts via `peter-evans/create-or-update-comment`
  patch in place instead of accumulating duplicate comments.
- **Cosign-signed releases.** Every archive carries a Sigstore signature
  via GitHub OIDC. Action defaults to verifying signatures; opt-out via
  `verify-signatures: false` for trusted mirrors. As of v0.9.6, the same
  cosign machinery can verify the **input SBOMs** themselves via
  `--before-attestation` / `--after-attestation`.
- **OSS-first, no telemetry, no account.** Apache-2.0; no daemon, no
  hosted UI, no signup.

## Where to next?

### Getting started
- New here? Start with the [Quickstart](./quickstart.md).
- Wiring up the GitHub Action? See [GitHub Action](./github-action.md).
- On another forge? See [GitLab CI](./gitlab-ci.md),
  [Bitbucket Pipelines](./bitbucket.md), or
  [Azure DevOps Pipelines](./azure-devops.md).
- Looking up a specific flag? See [CLI reference](./cli-reference.md).

### Suppressing findings
- [Baseline & suppression](./baseline.md) — JSON snapshots, in-comment
  `/bomdrift suppress`, `expires` + `reason`.
- [License policy](./license-policy.md) — SPDX expression evaluation
  with allow/deny + per-exception granularity.
- [VEX](./vex.md) — OpenVEX 0.2.0 + CycloneDX VEX 1.6 consume / emit.

### Output
- [Output formats](./output-formats.md) — markdown / terminal / JSON.
- [SARIF + Code Scanning](./sarif.md) — stable rule IDs, fingerprints,
  Code Scanning ingestion.

### Per-signal deep dives
- [Enrichers overview](./enrichers/overview.md) — the contract every
  enricher honors, plus pointers into each chapter.

### Advanced
- [OCI attestation](./attestation.md) — fetch SBOMs as
  `cosign verify-attestation`-verified OCI artifacts (v0.9.6+).
- [Plugins](./plugins.md) — external-process plugin protocol for
  custom rules (v0.9.6+).
- [Architecture](./architecture.md) — module map, pipeline,
  determinism contract.
