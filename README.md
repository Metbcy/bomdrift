# bomdrift

> SBOM diff with supply-chain risk signals — flags **new CVEs**, **typosquats**, and **young maintainers** on added or upgraded dependencies, surfaced as a GitHub PR comment.

**Status:** pre-alpha. v0.1.0 in active development. Star the repo for release notifications.

## Why?

After Shai-Hulud (npm, Nov 2025), the xz-utils backdoor (Mar 2024), and continual PyPI typosquat campaigns, the most actionable supply-chain question on a PR is:

> *What changed in this diff's dependencies that I should worry about?*

— not *"what's in my SBOM?"*. Plenty of tools answer the second question. **bomdrift answers the first.**

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
