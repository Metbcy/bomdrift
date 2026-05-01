# Project status

bomdrift is a single Rust binary + multi-SCM action that diffs two SBOMs
and surfaces supply-chain risk signals at PR time. The v0.9.x line shipped
the last items off the public feature roadmap (calibration knobs, OCI
attestation, plugins) and v0.9.9 closes out the **distribution** push:
`cargo install bomdrift`, `docker run ghcr.io/metbcy/bomdrift`, SLSA
build provenance, docs.rs auto-build, and a polished GitHub Marketplace
listing all work as of v0.9.9.

The project remains OSS-first: no hosted dashboard, no account, no
telemetry.

## What's new in v0.9.9

The "distribution release." No source-code feature work — the binary is
functionally identical to v0.9.8 — but every install path now works in
one command, and every release artifact carries both a cosign signature
and a SLSA build provenance attestation.

1. **`cargo install bomdrift` works.** Published to crates.io. Cargo
   metadata gains `documentation`, an `exclude` list trimming the
   crate to 220 KiB compressed, and a `[package.metadata.docs.rs]`
   block so the auto-built docs page renders cleanly. New
   `publish-dry-run` PR-time CI guard catches metadata regressions
   before the next release tag.
2. **`docker run ghcr.io/metbcy/bomdrift:v0.9.9` works.** Multi-arch
   (linux/amd64, linux/arm64) distroless image published to GitHub
   Container Registry on every release. Single-stage Dockerfile;
   consumes the cosign-signed binaries from the release matrix —
   no `cargo build` runs in the image. Tag matrix `:vX.Y.Z`, `:vX.Y`,
   `:vX`, `:latest`. Inline SLSA attestation on the image manifest.
3. **SLSA build provenance.** Every release archive AND the multi-arch
   ghcr.io image carry `actions/attest-build-provenance@v2`
   attestations. Verify with `gh attestation verify --owner Metbcy
   <archive>` or `slsa-verifier`. cosign keyless signatures continue
   in parallel — see [release-signing.md](docs/src/release-signing.md)
   for the cosign + SLSA threat-model framing.
4. **Marketplace polish + README badges.** crates.io, docs.rs, and
   GitHub Marketplace badges added at the top of the README. The
   Marketplace listing description was rewritten to lead with the
   axios narrative.
5. **Automated `v1` major-tag retag.** `release.yml` now force-pushes
   the major-version tag (currently `v1`; `v${major}` once v1.0.0
   ships) to point at the latest release. Marketplace + sloppy
   adopters consume the floating tag and now get the latest release
   automatically.

Manual recovery capability shipped alongside: a new `rebuild-docker.yml`
workflow (`workflow_dispatch` with a `tag` input) lets a maintainer
rebuild + push the docker image for any tag without re-cutting the
whole release. It reads the current `Dockerfile` from `main`, so any
future Dockerfile fix can rebuild any past tag's image.

## What's new in v0.9.8

The "code-review-driven hardening" milestone:

- **Continuous parser fuzzing** via `cargo-fuzz` against CycloneDX,
  SPDX, and Syft JSON parsers. PR-time short pass + weekly long
  scheduled run. See [development/fuzzing.md](docs/src/development/fuzzing.md).
- **CI coverage report** via `cargo-llvm-cov` with a sticky PR comment.
  Informational; `--fail-under-lines` will be added once coverage is
  visible across 2–3 releases.
- **`unwrap`/`expect`/`panic`/`todo`/`unimplemented` lints warn at
  crate root.** Production code audited; remaining `.expect()` sites
  carry rationale comments. Zero production `.unwrap()` remain.
- **`unsafe` blocks all carry `// SAFETY:` comments** and the
  `clippy::undocumented_unsafe_blocks` lint enforces it going
  forward.
- **`src/lib.rs` 47 KB → 31 lines.** Extracted the `run_diff`
  orchestration into `src/run.rs`. Public API surface preserved
  byte-for-byte.

Full notes for both releases live in [CHANGELOG.md](./CHANGELOG.md).

## Current support

| Area | Status |
|---|---|
| `cargo install bomdrift` | Supported (v0.9.9+) — see [crates.io](https://crates.io/crates/bomdrift) |
| `docker run ghcr.io/metbcy/bomdrift` | Supported (v0.9.9+) — multi-arch (amd64, arm64), distroless |
| GitHub.com pull requests | Supported through `Metbcy/bomdrift@v1` — see [github-action.md](docs/src/github-action.md) |
| Local CLI binary | Supported on Linux x86_64 + aarch64, macOS aarch64, Windows x86_64 — see [quickstart.md](docs/src/quickstart.md) |
| SBOM formats | CycloneDX 1.5 / 1.6 JSON, SPDX 2.3 JSON, Syft JSON |
| In-comment suppression (GitHub) | Supported through `Metbcy/bomdrift/comment-suppress@v1` — see [baseline.md](docs/src/baseline.md#in-comment-suppression-v05) |
| GitHub Code Scanning (SARIF upload) | Supported (v0.8+) — set `upload-to-code-scanning: 'true'`; see [sarif.md](docs/src/sarif.md) |
| EPSS exploit-prediction scoring | Supported (v0.8+) — auto, opt-out via `--no-epss`; see [enrichers/epss.md](docs/src/enrichers/epss.md) |
| CISA KEV (known-exploited) flagging | Supported (v0.8+) — auto, opt-out via `--no-kev`; see [enrichers/kev.md](docs/src/enrichers/kev.md) |
| License allow/deny policy | Supported (v0.8+, full SPDX expression evaluation v0.9, per-exception `WITH`-clause granularity v0.9.5) — see [license-policy.md](docs/src/license-policy.md) |
| Suppression expiry (`expires` + `reason`) | Supported (v0.8+) — time-boxed risk acceptance; see [baseline.md](docs/src/baseline.md#time-boxed-suppressions-expires--reason) |
| GitLab CI merge requests | Supported through `examples/gitlab-ci/` (v0.7+); comment-driven `/bomdrift suppress` via Cloudflare Worker bridge (v0.9+); see [gitlab-ci.md](docs/src/gitlab-ci.md) |
| Bitbucket Cloud Pipelines | Supported (v0.9+) — `examples/bitbucket-pipelines/`; comment-driven suppression via Worker bridge (v0.9.5+); see [bitbucket.md](docs/src/bitbucket.md) |
| Azure DevOps Pipelines | Supported (v0.9+) — `examples/azure-devops/`; comment-driven suppression via Worker bridge (v0.9.5+); see [azure-devops.md](docs/src/azure-devops.md) |
| VEX consume / emit | Supported (v0.9+) — OpenVEX 0.2.0 + CycloneDX VEX 1.6; see [vex.md](docs/src/vex.md) |
| Registry-metadata enrichers (npm/PyPI/crates.io) | Supported (v0.9+) — recently-published, deprecated, maintainer-set-changed; see [enrichers/registry.md](docs/src/enrichers/registry.md) |
| Calibration knobs (similarity / young-maintainer / cache TTL) | Supported (v0.9.6+) — see [cli-reference.md](docs/src/cli-reference.md#calibration) |
| OCI attestation verification | Supported (v0.9.6+) — via `cosign verify-attestation` shell-out; see [attestation.md](docs/src/attestation.md) |
| Custom rules / plugin system | Supported (v0.9.6+) — external-process plugins via `--plugin <manifest>`; see [plugins.md](docs/src/plugins.md) |
| Continuous parser fuzzing | Supported (v0.9.8+) — `cargo-fuzz` libfuzzer targets, weekly cron + PR triggers |
| Coverage report (informational) | Supported (v0.9.8+) — sticky PR comment with line %, no fail-under gate yet |
| SLSA build provenance | Supported (v0.9.9+) — `actions/attest-build-provenance@v2` on archives + ghcr.io image; see [release-signing.md](docs/src/release-signing.md) |
| GitHub Enterprise / self-hosted runners | Expected to work, not broadly tested yet |
| Hosted dashboard / SaaS | Not planned |

## Out-of-scope by design

bomdrift's design constraints (OSS-first, single-binary, no
telemetry, change-focused) put a number of capabilities deliberately
out of scope. Pair bomdrift with the suggested complementary tools
when you need them — see the README's
[Non-goals](https://github.com/Metbcy/bomdrift#non-goals) section
for the rationale.

| Out-of-scope | Pair with |
|---|---|
| SBOM generation | Syft (bomdrift bundles this in the Action) |
| Reachability / call-graph analysis | Endor Labs, Snyk Reachability |
| Tarball / behavior analysis | Socket |
| Auto-fix PR generation | Renovate, Dependabot |
| Container / OCI image scanning | Trivy, Grype |
| SAST / secrets scanning | GitHub Advanced Security, Semgrep, gitleaks |
| Risk-score dashboards (cross-repo) | Endor, Snyk |
| Web UI / hosted dashboard | n/a — out of scope |
| Continuous monitoring / always-on agent | Run bomdrift in scheduled CI |
| Per-language deep parsing beyond Syft | Use a richer SBOM generator upstream |
| Closed-source advisory feeds | bomdrift uses OSV.dev only |

## Known limitations

- The zero-config Action path is built for `pull_request` workflows. For
  `push`, `schedule`, or `workflow_dispatch`, set `before-ref` and
  `after-ref` explicitly or provide `before-sbom` / `after-sbom`.
- OSV.dev and maintainer-age enrichers are best-effort network calls. The
  diff still renders when those services are unavailable, but affected
  signals may be absent.
- The comment-suppress companion action currently suppresses an advisory ID
  across all components. Use a hand-curated baseline entry when you need
  per-component suppression.
- The ghcr.io image uses the `gcr.io/distroless/cc-debian13:nonroot`
  base (GLIBC 2.41) to match the GLIBC version the GitHub Actions
  `ubuntu-latest` runner produces binaries against. Don't downgrade
  the base without first moving the release matrix to an older
  runner.

## Feedback wanted

The highest-value feedback is false positives and workflow adoption reports:

1. File a false-positive issue with the finding ID, package, version, and a
   minimal SBOM pair if possible.
2. Open an action-broke issue if the zero-config workflow fails in your repo.
3. Comment on the pinned adoption issue once it exists with the ecosystem and
   repository shape where you tried bomdrift.
