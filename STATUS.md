# Project status

bomdrift is usable today as a local CLI and as a composite GitHub Action,
with first-class templates + comment-driven suppression bridges for GitLab
CI, Bitbucket Pipelines, and Azure DevOps Pipelines. The v0.9.6 line ships
the last items off the public roadmap (calibration knobs, OCI attestation,
a plugin system) while keeping the project OSS-first: no hosted dashboard,
no account, no telemetry.

## What's new in v0.9.6

Four feature themes for skim-readers; full notes live in
[CHANGELOG.md](./CHANGELOG.md):

1. **Cache-TTL unification.** The four duplicated `CACHE_TTL_SECS`
   constants (OSV, EPSS, KEV, registry) collapse into one shared
   `enrich::cache::CACHE_TTL_SECS`. No behavior change at the default,
   but a single source of truth for the calibration knob below.
2. **Calibration knobs.** Three previously hardcoded thresholds become
   user-tunable: `--typosquat-similarity-threshold` (default 0.92),
   `--young-maintainer-days` (default 90), `--cache-ttl-hours`
   (default 24). Matching `[diff]` config keys, all CLI-overridable.
3. **OCI attestation verification.** New `--before-attestation` /
   `--after-attestation` flags fetch the SBOM from an OCI registry as
   a `cosign verify-attestation`-verified artifact. Required pair:
   `--cosign-identity` (regex) + `--cosign-issuer` (URL).
   `--require-attestation` refuses to fall back to local files. See
   [docs/src/attestation.md](docs/src/attestation.md).
4. **External-process plugin system.** New `--plugin <manifest.toml>`
   (repeatable) lets organizations layer custom rules on top of
   bomdrift's bundled enrichers. JSON over stdin/stdout; fail-soft.
   Worked example at [`examples/plugins/banned-packages/`](examples/plugins/banned-packages/);
   protocol reference at [docs/src/plugins.md](docs/src/plugins.md).

## Current support

| Area | Status |
|---|---|
| GitHub.com pull requests | Supported through `Metbcy/bomdrift@v1` — see [github-action.md](docs/src/github-action.md) |
| Local CLI | Supported on Linux x86_64 + aarch64, macOS aarch64, Windows x86_64 — see [quickstart.md](docs/src/quickstart.md) |
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
- GitHub Marketplace publication is a repository setting. The action metadata
  is ready, but a maintainer must enable the listing in GitHub settings.

## Feedback wanted

The highest-value feedback is false positives and workflow adoption reports:

1. File a false-positive issue with the finding ID, package, version, and a
   minimal SBOM pair if possible.
2. Open an action-broke issue if the zero-config workflow fails in your repo.
3. Comment on the pinned adoption issue once it exists with the ecosystem and
   repository shape where you tried bomdrift.
