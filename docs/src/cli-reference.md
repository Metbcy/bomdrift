# CLI reference

This page documents every `bomdrift` subcommand and flag. The authoritative
help text is `bomdrift --help` / `bomdrift <subcommand> --help`; this page
groups the same information by behavior so it's easier to look up.

## Subcommands

```text
bomdrift diff <BEFORE> <AFTER> [OPTIONS]
bomdrift init [--config-only] [--force]
bomdrift baseline add <ID> [--path <PATH>]
bomdrift refresh-typosquat [--ecosystem <ECOSYSTEM>]
```

## `bomdrift diff`

Diff two SBOMs and surface supply-chain risk signals on changed components.

### Positional arguments

- `<BEFORE>` — path to the "before" SBOM (CycloneDX 1.5/1.6, SPDX 2.3, or Syft JSON).
- `<AFTER>`  — path to the "after" SBOM.

### Output flags

#### `--output <FORMAT>`

Output format. One of:

- `terminal` — ANSI-colored tree-style output for human consumption. The
  default when stdout is a TTY.
- `markdown` — GitHub-Flavored Markdown ready for PR-comment posting.
  The default when stdout is piped/redirected.
- `json` — pretty-printed `{"changes": ..., "enrichment": ...}` graph
  for downstream tooling.
- `sarif` — SARIF v2.1.0 for GitHub Code Scanning ingestion.

#### `--format <FORMAT>`

Force input format detection. One of `auto` (default), `cdx`, `spdx`, `syft`.

`auto` looks at the JSON top-level fields to dispatch (`bomFormat` for
CycloneDX, `spdxVersion` for SPDX, `schema` for Syft). Force-pinning is
useful when an SBOM lacks the canonical magic markers.

#### `--summary-only`

Markdown-only. Emits just the summary table + a footer pointing at the
full output. Used by the action's comment-size fallback when the full
diff exceeds GitHub's 65,536-char comment-body cap.

#### `--findings-only`

Markdown-only. Keeps the summary table and risk-bearing sections
(vulnerabilities, typosquats, version jumps, young maintainers, license
changes) but omits raw Added / Removed / Version changed detail tables.
This is useful when a PR intentionally updates a large lockfile and
reviewers only want the actionable findings inline.

The counts still appear in the summary table, so churn is visible even
when the long per-dependency rows are hidden.

### Repo policy config

#### `--config <PATH>`

Load defaults from a `.bomdrift.toml` policy file. When omitted,
`bomdrift diff` auto-loads `.bomdrift.toml` from the current working
directory if it exists; missing default config is ignored. An explicit
`--config` path must exist and parse.

CLI flags override config values for one-off runs. Positive booleans in
config, such as `findings_only = true`, turn the behavior on; v0.6 does
not add parallel `--no-*` flags to turn those booleans off from the CLI.

Example:

```toml
[diff]
fail_on = "critical-cve"
baseline = ".bomdrift/baseline.json"
findings_only = true
max_added = 25
max_version_changed = 10
```

Supported `[diff]` keys map to the CLI flags: `output`, `format`,
`no_osv`, `no_osv_cache`, `baseline`, `no_maintainer_age`, `fail_on`,
`summary_only`, `findings_only`, `include_file_components`, `repo_url`,
`platform`, `max_added`, `max_removed`, and `max_version_changed`.

### Forge / CI integration

#### `--platform <PLATFORM>`

`github` (default), `gitlab`, `bitbucket`, or `azure-devops`. Drives
the rendered markdown comment's footer:

- `github` — `/issues/new?...` URL shape, `/bomdrift suppress <ID>`
  comment-driven flow (requires the [comment-suppress
  sub-action](./baseline.md#in-comment-suppression-v05)).
- `gitlab` — `/-/issues/new?issuable_template=false-positive` URL
  shape, points reviewers at `bomdrift baseline add <ID>` (with an
  optional advanced webhook bridge for in-comment suppression — see
  [GitLab CI](./gitlab-ci.md)).
- `bitbucket` — `/issues/new` URL shape, `bomdrift baseline add <ID>`
  manual suppression flow.
- `azure-devops` — `/_workitems/create?templateName=false-positive`
  URL shape, `bomdrift baseline add <ID>` manual suppression flow.

When the flag is omitted, bomdrift auto-detects from CI environment
variables in this order: `GITLAB_CI=true` → GitLab,
`BITBUCKET_BUILD_NUMBER` → Bitbucket, `TF_BUILD` → Azure DevOps,
otherwise GitHub. The explicit flag always wins. Also configurable
via `[diff] platform = "<value>"` in `.bomdrift.toml`.

Set in lockstep with `--repo-url` (or `BOMDRIFT_REPO_URL`, or — on
GitLab CI — `CI_PROJECT_URL`). Without a URL the footer is omitted
entirely; the platform flag controls only the footer's *shape*.

See [GitLab CI](./gitlab-ci.md) for the full template.

### Enrichment flags

#### `--no-osv`

Skip OSV.dev CVE enrichment entirely. Use for offline runs and tests.
Equivalent to `--fail-on=cve` not tripping (no vulns to trip on).

#### `--no-osv-cache`

Bypass the on-disk OSV severity cache at `<XDG_CACHE_HOME>/bomdrift/osv/`.
Use for paranoid reruns where you want fresh fetches even within the
24h TTL window. The cache is purely an optimization — `--no-osv-cache`
always works.

#### `--no-maintainer-age`

Skip the maintainer-age enricher (no GitHub API calls). Use for offline
runs and tests; required when `GITHUB_TOKEN` is unset and the
unauthenticated rate limit (60/hr) is too low for the diff being
analyzed.

### Failure thresholds

#### `--fail-on <THRESHOLD>`

Exit with code 2 when findings of the configured threshold surface. One of:

- `none` — never trips (default).
- `cve` — trips on any CVE / GHSA / MAL advisory finding.
- `critical-cve` — trips when at least one finding has `severity >= High`
  per the OSV-fetched severity. The "critical" name covers the
  HIGH-or-CRITICAL bucket; CRITICAL alone is rare in GHSA tagging, and
  many actively-exploited advisories ship as HIGH.
- `typosquat` — trips on any typosquat finding (always `severity = none`,
  but the threshold lets you gate on the structural signal).
- `license-change` — trips on same-version license changes.
- `any` — trips on any finding (CVE, typosquat, version-jump,
  maintainer-age) OR any license-changed-without-version-bump.

The PR-comment body is written to stdout **before** exit-2 — the action's
`tee` + `PIPESTATUS` wrapper relies on this so the comment posts even
when the workflow step fails.

#### Diff budgets

`--max-added <N>`, `--max-removed <N>`, and
`--max-version-changed <N>` fail the run with exit code 2 when a diff
exceeds the configured dependency-churn budget. The rendered body is
still written before exit, just like `--fail-on`, so GitHub Actions can
post the PR comment and then block the merge.

#### `--baseline <PATH>`

Path to a previously captured `bomdrift diff --output json` snapshot.
Findings present in the baseline are suppressed from the rendered output
and from the `--fail-on` trip-evaluation. Match keys are conservative —
a finding at a different version than baseline still surfaces. See
[Baseline & suppression](./baseline.md) for full match-key semantics.

## `bomdrift init`

Scaffold a copy-paste adoption setup in the current repository:

```bash
bomdrift init
```

This writes:

- `.bomdrift.toml`
- `.github/workflows/sbom-diff.yml`
- `.github/workflows/bomdrift-suppress.yml`

Flags:

- `--config-only` — write only `.bomdrift.toml`.
- `--force` — overwrite existing generated files. Without `--force`,
  existing files are preserved and the command fails loudly.

## `bomdrift refresh-typosquat`

Refresh the bundled typosquat top-package lists from upstream sources.

### Flags

#### `--ecosystem <ECOSYSTEM>`

Which ecosystem's list to refresh. One of:

- `all` — refresh every ecosystem with a wired-up fetcher (default).
  Expands to all eight supported ecosystems as of v0.4.
- `npm` — top-1000 from the anvaka/npmrank gist.
- `pypi` — top-200 from hugovk/top-pypi-packages.
- `cargo` — top-200 from the crates.io API (paginated, polite 1 req/s).
- `nuget` — top-200 from the nuget.org v3 search API
  (`orderby=totalDownloads&take=200`). No pagination at this list size.
- `maven` / `go` / `gem` / `composer` — accepted but no-op. Each
  ecosystem lacks a stable public popularity feed; the curated
  `data/<eco>-top*.txt` snapshots shipped in the binary remain the
  source of truth. Refreshing those means editing the file and
  rebuilding.

Refreshed lists are written to `<XDG_CACHE_HOME>/bomdrift/typosquat/<eco>.txt`
via temp-file + atomic rename. The typosquat enricher prefers cache files
over the embedded snapshot when present and parseable.

## Calibration

#### `--debug-calibration`

Off by default. When set, `bomdrift diff` writes one
pipe-delimited line to stderr per finding it considers, with the
schema:

```
kind|key|score|threshold
```

`kind` is one of `typosquat`, `version-jump`, `maintainer-age`, or
`cve`. `key` is a stable identifier (the package purl, advisory ID,
etc.). `score` and `threshold` are the numeric inputs to the
gating decision — for `cve` the score column carries the severity
bucket label rather than a numeric CVSS score (bomdrift doesn't
parse CVSS numerically).

Pipe-delimited because purls contain commas. The flag is purely
diagnostic — it doesn't change which findings get rendered. Pipe
to a file:

```bash
bomdrift diff old.cdx.json new.cdx.json --debug-calibration 2> calibration.tsv
```

If you collect a calibration sample across many PRs and have a
hunch on a better default for `SIMILARITY_THRESHOLD` /
`YOUNG_MAINTAINER_DAYS`, please share on issue
[#5](https://github.com/Metbcy/bomdrift/issues/5) — there is no
telemetry; you own the file.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success. |
| 1 | bomdrift internal error (parse failure, network mishap not gated by best-effort path, etc.). |
| 2 | `--fail-on` threshold or diff budget tripped. The body is still on stdout — the action posts it before propagating the exit code. |
| (clap 2) | Usage error from clap (unknown flag, missing required argument). Distinguishable from exit-2 from `--fail-on` by stderr containing `error: ...` rather than the v0.2 caveat warning. |

## Environment variables

| Variable | Purpose |
|---|---|
| `GITHUB_TOKEN` | Bumps the GitHub REST rate limit from 60/hr unauth to 5000/hr authenticated, used by the maintainer-age enricher. |
| `BOMDRIFT_REPO_URL` | Fallback for `--repo-url` when the flag isn't passed. Used to render the comment footer's "Report this finding" / "Suppress" links. |
| `GITLAB_CI` | When `true`, auto-selects `--platform gitlab` (unless overridden). |
| `CI_PROJECT_URL` | On GitLab CI, used as a final fallback for `--repo-url` after `BOMDRIFT_REPO_URL`. |
| `XDG_CACHE_HOME` | Cache root for the OSV severity cache and the refreshed typosquat lists. Defaults to `~/.cache` on Linux. |
| `NO_COLOR` | Honored by the terminal renderer; falls back to plain output. |
| `CLICOLOR_FORCE` | Honored by the terminal renderer; forces ANSI even on a non-TTY. |
