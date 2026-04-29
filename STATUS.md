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
| GitLab CI merge requests | Supported through the `examples/gitlab-ci/` template (v0.7+); in-comment suppression deferred to v0.9 |
| GitHub Enterprise / self-hosted runners | Expected to work, not broadly tested yet |
| Bitbucket / Azure DevOps | Planned for v0.9 |
| VEX consume / emit | Planned for v0.9 |
| Hosted dashboard / SaaS | Not planned |

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
