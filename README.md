# bomdrift

> SBOM diff with supply-chain risk signals — flags **new CVEs**, **typosquats**, and **young maintainers** on added or upgraded dependencies, surfaced as a GitHub PR comment.

**Status:** pre-alpha. v0.1.0 in active development. Star the repo for release notifications.

## Why?

The most actionable supply-chain question on a pull request is:

> *What changed in this diff's dependencies that I should worry about?*

— not *"what's in my SBOM?"*. Plenty of tools answer the second question. **bomdrift answers the first.**

Recent incidents bomdrift would have surfaced:

- **axios npm compromise (Mar 31, 2026)** — maintainer was socially engineered (fake Slack/Teams call, North Korean UNC1069), and `axios@1.14.1` + `axios@0.30.4` shipped with a malicious runtime dep `plain-crypto-js@4.2.1` that dropped the WAVESHAPER.V2 RAT on Windows/macOS/Linux. Three of bomdrift's signals would have fired in the diff: a **brand-new transitive dependency**, a **typosquat** (`plain-crypto-js` vs the legitimate `crypto-js` — Jaro-Winkler ≈ 0.96), and a **young-maintainer** flag on the new package's author. 70M+ weekly downloads of axios were exposed.
- **Shai-Hulud worm (npm, Nov 2025)** — 700+ packages compromised by a self-replicating worm. Diff-time review of newly added transitive deps and version bumps was the only pre-merge defense.
- **xz-utils backdoor (CVE-2024-3094, Mar 2024)** — 2.6-year social-engineering campaign culminating in a backdoor shipped in 5.6.0/5.6.1. The "Jia Tan" maintainer's first commit was recent relative to the release — exactly the maintainer-age heuristic bomdrift implements.
- **Sustained PyPI typosquat campaigns (2024–2026)** — hundreds of malicious packages disguised by single-character substitutions (`sysaws` → `sisaws`, etc.) — Jaro-Winkler against PyPI's top-N catches these reliably.

## Features (planned for v0.1.0)

- Diff **CycloneDX**, **SPDX**, and **Syft** JSON SBOMs against each other (any combination).
- For added & upgraded packages, enrich with **OSV.dev CVE data**.
- Flag possible **typosquats** via Jaro-Winkler similarity to top-package lists per ecosystem (npm/PyPI/crates.io/Maven).
- Flag deps whose **top maintainer joined the project recently** — the canonical xz-style takeover signal.
- Flag **multi-major version jumps** in a single diff (often correlates with takeover swaps and namespace reuse).
- Output formats: terminal (colored), Markdown (PR comment), JSON, SARIF.
- Ship as a single Rust binary **and** a GitHub Action — composite, no Docker.
- Releases are signed with [cosign](https://docs.sigstore.dev/) — eat-your-own-supply-chain-dogfood.

## Non-goals

- **SBOM generation.** Use [Syft](https://github.com/anchore/syft) — it's already great. bomdrift only consumes SBOMs.
- **Dependency-tree visualization.** [Cargo-tree](https://doc.rust-lang.org/cargo/commands/cargo-tree.html), [`pnpm why`](https://pnpm.io/cli/why), and friends do this well.
- **Replacing your SCA scanner.** OSV-scanner, Grype, Trivy all have richer vulnerability databases. bomdrift's CVE enrichment is *change-focused*: only on what's new in this diff.

## License

Apache-2.0 — see [LICENSE](./LICENSE).
