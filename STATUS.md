# Project status

bomdrift is usable today as a local CLI and GitHub Action. The v0.5 line
focuses on making the Action copy-pasteable for first-time users while
keeping the project OSS-first: no hosted dashboard, no account, no telemetry.

## Current support

| Area | Status |
|---|---|
| GitHub.com pull requests | Supported through `Metbcy/bomdrift@v1` |
| Local CLI | Supported on Linux x86_64/aarch64, macOS aarch64, Windows x86_64 |
| SBOM formats | CycloneDX JSON, SPDX JSON, Syft JSON |
| In-comment suppression (GitHub) | Supported through `Metbcy/bomdrift/comment-suppress@v1` |
| GitHub Code Scanning (SARIF upload) | Supported (v0.8+) — set `upload-to-code-scanning: 'true'` |
| EPSS exploit-prediction scoring | Supported (v0.8+) — auto, opt-out via `--no-epss` |
| CISA KEV (known-exploited) flagging | Supported (v0.8+) — auto, opt-out via `--no-kev` |
| License allow/deny policy | Supported (v0.8+) — `[license]` block / CLI flags |
| Suppression expiry (`expires` + `reason`) | Supported (v0.8+) — time-boxed risk acceptance |
| GitLab CI merge requests | Supported through the `examples/gitlab-ci/` template (v0.7+); comment-driven suppression supported via Cloudflare Worker bridge (v0.9+) |
| GitHub Enterprise / self-hosted runners | Expected to work, not broadly tested yet |
| Bitbucket Pipelines | Supported (v0.9+) — `examples/bitbucket-pipelines/`; comment-driven suppression via Cloudflare Worker bridge (v0.9.5+) |
| Azure DevOps Pipelines | Supported (v0.9+) — `examples/azure-devops/`; comment-driven suppression via Cloudflare Worker bridge (v0.9.5+) |
| VEX consume / emit | Supported (v0.9+) — OpenVEX 0.2.0 + CycloneDX VEX 1.6 |
| SPDX expression evaluation | Supported (v0.9+) — full `Expression::evaluate` via `spdx` crate |
| Registry-metadata enrichers (npm/PyPI/crates.io) | Supported (v0.9+) — recently-published, deprecated, maintainer-set-changed |
| Custom rules / plugin system | Supported (v0.9.6+) — external-process plugins via `--plugin <manifest>`; see [docs/src/plugins.md](docs/src/plugins.md) |
| OCI attestation verification | Supported (v0.9.6+) — via `cosign verify-attestation` shell-out; see [docs/src/attestation.md](docs/src/attestation.md) |
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
| Reachability / call-graph analysis | Endor Labs, Snyk Reachability |
| Tarball / behavior analysis | Socket |
| Auto-fix PR generation | Renovate, Dependabot |
| Container / OCI image scanning | Trivy, Grype |
| SAST / secrets scanning | GitHub Advanced Security, Semgrep, gitleaks |
| Risk-score dashboards (cross-repo) | Endor, Snyk |
| Continuous monitoring / always-on agent | Run bomdrift in scheduled CI |
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
- GitHub Marketplace publication is a repository setting. The action metadata
  is ready, but a maintainer must enable the listing in GitHub settings.

## Feedback wanted

The highest-value feedback is false positives and workflow adoption reports:

1. File a false-positive issue with the finding ID, package, version, and a
   minimal SBOM pair if possible.
2. Open an action-broke issue if the zero-config workflow fails in your repo.
3. Comment on the pinned adoption issue once it exists with the ecosystem and
   repository shape where you tried bomdrift.
