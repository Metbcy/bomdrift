# CLI reference

This page documents every `bomdrift` subcommand and flag. The authoritative
help text is `bomdrift --help` / `bomdrift <subcommand> --help`; this page
groups the same information by behavior so it's easier to look up. Each
flag carries an *introduced-in* annotation so future readers can reason
about which version a feature first shipped in.

## Subcommands

```text
bomdrift diff <BEFORE> <AFTER> [OPTIONS]
bomdrift init [--config-only] [--force]
bomdrift baseline add [<ID>] [--path <PATH>] [--expires <YYYY-MM-DD>] [--reason <TEXT>] [--from-comment <BODY>]
bomdrift refresh-typosquat [--ecosystem <ECOSYSTEM>]
```

| Subcommand | Purpose |
|---|---|
| [`diff`](#bomdrift-diff) | Diff two SBOMs and emit findings. The everything-flag. |
| [`init`](#bomdrift-init) | Scaffold `.bomdrift.toml` + GitHub workflows. |
| [`baseline add`](#bomdrift-baseline-add) | Append an advisory ID to a baseline file. |
| [`refresh-typosquat`](#bomdrift-refresh-typosquat) | Re-fetch the bundled top-package lists. |

## `bomdrift diff`

Diff two SBOMs and surface supply-chain risk signals on changed components.

### Positional arguments

- `<BEFORE>` — path to the "before" SBOM (CycloneDX 1.5/1.6, SPDX 2.3, or
  Syft JSON). Optional when `--before-attestation` is set instead.
- `<AFTER>`  — path to the "after" SBOM. Optional when
  `--after-attestation` is set instead.

### Output formats

#### `--output <FORMAT>`
*Introduced in v0.1.*

Output format. One of:

- `terminal` — ANSI-colored tree-style output. Default when stdout is a TTY.
- `markdown` — GitHub-Flavored Markdown ready for PR-comment posting.
  Default when stdout is piped/redirected.
- `json` — pretty-printed `{"changes": ..., "enrichment": ...}` graph.
- `sarif` — SARIF v2.1.0 for GitHub Code Scanning ingestion.

Config key: `[diff] output`.

#### `--output-file <PATH>`
*Introduced in v0.8.*

Write the chosen `--output` format to this path instead of stdout. Useful
for SARIF (`--output sarif --output-file bomdrift.sarif`) where YAML
quoting `>` redirection is fragile in CI templates.

#### `--format <FORMAT>`
*Introduced in v0.1.*

Force input format detection. `auto` (default) / `cdx` / `spdx` / `syft`.
`auto` looks at the JSON top-level fields to dispatch.

#### `--summary-only`
*Introduced in v0.3.* Markdown-only.

Emits just the summary table + a footer pointing at the full output. Used
by the action's comment-size fallback when the full diff exceeds GitHub's
65,536-char comment-body cap.

#### `--findings-only`
*Introduced in v0.6.* Markdown-only.

Keeps the summary table and risk-bearing sections (vulnerabilities,
typosquats, version jumps, young maintainers, license changes,
registry-metadata findings) but omits raw Added / Removed / Version
changed detail tables. Useful when a PR intentionally updates a large
lockfile and reviewers only want the actionable findings inline.

#### `--include-file-components`
*Introduced in v0.5.*

Keep `Ecosystem::Other("file")` pseudo-components emitted by Syft's
directory cataloger. Off by default — those produce phantom Added/Removed
pairs that drown real package changes.

### Repo policy config

#### `--config <PATH>`
*Introduced in v0.6.*

Load defaults from a `.bomdrift.toml` policy file. When omitted, an
existing `.bomdrift.toml` in the current working directory is loaded
automatically; missing default config is ignored. An explicit `--config`
path must exist and parse.

CLI flags override config values for one-off runs.

Example `.bomdrift.toml`:

```toml
[diff]
fail_on = "critical-cve"
baseline = ".bomdrift/baseline.json"
findings_only = true
max_added = 25
max_version_changed = 10

# Calibration knobs (v0.9.6+)
typosquat_similarity_threshold = 0.92
young_maintainer_days = 90
cache_ttl_hours = 24

[license]
allow = ["Apache-2.0", "MIT", "BSD-*"]
deny = ["GPL-*", "AGPL-*"]
allow_exceptions = ["LLVM-exception", "Classpath-exception-2.0"]
```

### Suppression

#### `--baseline <PATH>`
*Introduced in v0.5.*

Path to a JSON snapshot whose findings should be suppressed from this
run's output (and from the `--fail-on` trip evaluation). Match keys are
conservative — a finding at a different version than baseline still
surfaces. See [Baseline & suppression](./baseline.md) for the schema and
match-key semantics.

#### `--vex <PATH>`
*Introduced in v0.9.* Repeatable.

Path(s) to VEX (Vulnerability Exploitability eXchange) files to consume.
Each file is auto-detected as either OpenVEX 0.2.0 or CycloneDX VEX 1.6.
Statements with status `not_affected` / `fixed` suppress matching
findings; `under_investigation` annotates without suppressing;
`affected` annotates as a no-op badge. See [VEX](./vex.md) for the
finding-id matching rules including the synthetic-id convention.

#### `--emit-vex <PATH>`
*Introduced in v0.9.*

Emit a single OpenVEX 0.2.0 doc covering every finding in the
post-baseline diff. Baseline-suppressed entries inherit their
`vex_status` from the baseline entry (defaulting to
`under_investigation`); un-suppressed findings emit as `affected`.

#### `--vex-author <STRING>`
*Introduced in v0.9.*

VEX `author` for `--emit-vex`. Falls back to `repo_url`, then to
`"bomdrift"`.

#### `--vex-default-justification <STRING>`
*Introduced in v0.9.*

Default OpenVEX `justification` written into emitted statements when
the source baseline entry doesn't supply one. Defaults to
`"vulnerable_code_not_in_execute_path"`.

### Enrichment toggles

Each of these disables one enricher entirely (no network, no cache
lookup). All default to **on**.

| Flag | Disables | Introduced |
|---|---|---|
| `--no-osv` | OSV.dev CVE lookup | v0.1 |
| `--no-osv-cache` | The 24h on-disk OSV severity cache only — keeps OSV enabled | v0.3 |
| `--no-maintainer-age` | GitHub-REST maintainer-age enricher | v0.2 |
| `--no-epss` | FIRST.org EPSS enricher | v0.8 |
| `--no-kev` | CISA KEV enricher | v0.8 |
| `--no-registry` | Registry-metadata enrichers (npm/PyPI/crates.io) | v0.9 |

#### `--recently-published-days <N>`
*Introduced in v0.9.*

Recently-published threshold in days for the registry enricher
(default `14`). Set to `0` to disable that specific kind without
disabling the other registry checks.

### Calibration

bomdrift's heuristic enrichers ship with conservative defaults that work
for most repos. When the defaults aren't right at scale, every threshold
is tunable either through `[diff]` keys in `.bomdrift.toml` or via the
matching CLI flag. CLI flags override config values for one-off runs.

#### `--typosquat-similarity-threshold <FLOAT>`
*Introduced in v0.9.6.*

Type: float in `[0.0, 1.0]`. Default: `0.92`.
Config key: `[diff] typosquat_similarity_threshold`.

Minimum normalized edit-distance similarity between a candidate package
name and a top-list entry before bomdrift flags it as a possible
typosquat. Higher values = stricter (fewer false positives, more false
negatives). Lowering to `0.85` catches softer near-misses; raising to
`0.95` only catches one- or two-character swaps on short names.

#### `--young-maintainer-days <N>`
*Introduced in v0.9.6.*

Type: positive integer (days). Default: `90`.
Config key: `[diff] young_maintainer_days`.

A package's top contributor whose oldest commit is newer than this many
days is flagged as a young-maintainer signal. Defaults to a quarter;
raise to `180` for stricter ecosystems, lower to `30` for tighter
signals.

#### `--cache-ttl-hours <N>`
*Introduced in v0.9.6.*

Type: positive integer (hours). Default: `24`.
Config key: `[diff] cache_ttl_hours`.

Time-to-live for the OSV / EPSS / KEV / registry-metadata caches under
`<XDG_CACHE_HOME>/bomdrift/`. The same TTL applies to all four caches
(v0.9.6 unified the previously duplicated constants). Lower to `1` for
fast-changing security feeds in long-running self-hosted runners; raise
to `168` (one week) when running offline.

### License policy

#### `--allow-licenses <LIST>` / `--deny-licenses <LIST>`
*Introduced in v0.8.* Comma-separated, repeatable.

SPDX license identifiers (or `*`-suffix globs) permitted / forbidden by
policy. Deny wins when a license matches both. CLI flag takes precedence
over `[license] allow` / `deny` in `.bomdrift.toml` (override, not
merge). v0.9 adds full SPDX expression evaluation via the `spdx` crate
so compound expressions like `(MIT OR GPL-3.0)` evaluate correctly.

#### `--allow-exception <LIST>` / `--deny-exception <LIST>`
*Introduced in v0.9.5.* Comma-separated, repeatable.

SPDX exception identifiers (e.g. `LLVM-exception`,
`Classpath-exception-2.0`) permitted / forbidden as the right-hand side
of a `WITH` clause. When set, `Apache-2.0 WITH <other>` violates policy
even if `Apache-2.0` is on the base allow list. Empty lists preserve
v0.9 behavior (exception treated as informational).

#### `--allow-ambiguous-licenses`
*Introduced in v0.8.*

When set, compound SPDX expressions like `(MIT OR GPL-3.0)` are
permitted. Off by default — fail-closed.

See [License policy](./license-policy.md) for the full evaluation
semantics.

### Failure thresholds

#### `--fail-on <THRESHOLD>`
*Introduced in v0.2; expanded across v0.4 / v0.8 / v0.9.*

Exit with code 2 when findings of the configured threshold surface. One of:

- `none` — never trips (default).
- `cve` — trips on any CVE / GHSA / MAL advisory finding.
- `critical-cve` — trips when at least one finding has `severity >= High`
  per the OSV-fetched severity. (Naming kept for back-compat — covers
  the HIGH-or-CRITICAL bucket; HIGH alone is the common
  actively-exploited case.)
- `typosquat` — trips on any typosquat finding.
- `license-change` — trips on same-version license changes.
- `kev` — trips on any advisory in the CISA KEV catalog (v0.8+).
- `recently-published` / `deprecated` — registry-metadata finding gates (v0.9+).
- `any` — trips on any finding.

The PR-comment body is written to stdout **before** exit-2 — the
action's `tee` + `PIPESTATUS` wrapper relies on this so the comment
posts even when the workflow step fails.

#### `--fail-on-epss <FLOAT>`
*Introduced in v0.8.*

Trip exit-2 when any advisory's EPSS score is >= this threshold
(`0.0` – `1.0`). Recommended starting point: `0.5` (top decile of
actively-exploited CVEs).

#### Diff budgets

`--max-added <N>`, `--max-removed <N>`, and `--max-version-changed <N>`
fail the run with exit code 2 when a diff exceeds the configured
dependency-churn budget. Introduced in v0.4. The rendered body is still
written before exit, just like `--fail-on`.

### Forge integration

#### `--platform <PLATFORM>`
*Introduced in v0.7; expanded in v0.9 (Bitbucket / Azure DevOps).*

`github` (default), `gitlab`, `bitbucket`, or `azure-devops`. Drives
the rendered markdown comment's footer:

- `github` — `/issues/new?...` URL shape, `/bomdrift suppress <ID>`
  comment-driven flow (requires the [comment-suppress
  sub-action](./baseline.md#in-comment-suppression-v05)).
- `gitlab` — `/-/issues/new?issuable_template=false-positive` URL
  shape; manual `bomdrift baseline add <ID>` flow or the optional
  Cloudflare Worker bridge for in-comment suppression. See
  [GitLab CI](./gitlab-ci.md).
- `bitbucket` — `/issues/new` URL shape; comment-bridge in v0.9.5+.
  See [Bitbucket](./bitbucket.md).
- `azure-devops` — `/_workitems/create?templateName=false-positive`
  URL shape; comment-bridge in v0.9.5+. See
  [Azure DevOps](./azure-devops.md).

When the flag is omitted, bomdrift auto-detects from CI environment
variables in this order: `GITLAB_CI=true` → GitLab,
`BITBUCKET_BUILD_NUMBER` → Bitbucket, `TF_BUILD` → Azure DevOps,
otherwise GitHub. The explicit flag always wins. Also configurable via
`[diff] platform = "<value>"` in `.bomdrift.toml`.

Set in lockstep with `--repo-url` (or `BOMDRIFT_REPO_URL`, or — on
GitLab CI — `CI_PROJECT_URL`). Without a URL the footer is omitted
entirely; the platform flag controls only the footer's *shape*.

#### `--repo-url <URL>`
*Introduced in v0.5.*

Repository URL used to render the markdown comment's
action-affordance footer. Falls back to `BOMDRIFT_REPO_URL` env var.

### Attestation (OCI-fetched SBOMs)

*All flags in this section introduced in v0.9.6.* See
[OCI attestation](./attestation.md) for end-to-end usage.

#### `--before-attestation <REFERENCE>`

Fetch the "before" SBOM as a `cosign verify-attestation`-verified
attestation attached to an OCI artifact instead of reading a local
file. Mutually exclusive with the positional `before` argument.
Requires `--cosign-identity` and `--cosign-issuer`.

#### `--after-attestation <REFERENCE>`

Same, for the "after" side. Mutually exclusive with the positional
`after` argument.

#### `--cosign-identity <REGEX>`

Regex passed to `cosign verify-attestation
--certificate-identity-regexp`. Required when either
`--before-attestation` or `--after-attestation` is set. Example:
`https://github.com/owner/.+`.

#### `--cosign-issuer <URL>`

URL passed to `cosign verify-attestation --certificate-oidc-issuer`.
Required alongside `--cosign-identity`. Example:
`https://token.actions.githubusercontent.com`.

#### `--require-attestation`

Refuse to fall back to local-file SBOMs: both sides MUST come from a
verified OCI attestation. Implies `--before-attestation` and
`--after-attestation` are both set.

### Plugins

#### `--plugin <MANIFEST>`
*Introduced in v0.9.6.* Repeatable.

Path to a plugin manifest TOML. Each plugin is an external executable
invoked once per added / version-changed component with JSON over
stdin/stdout. Plugin failures (timeout, non-zero exit, malformed JSON)
drop their findings without failing the diff. See [Plugins](./plugins.md)
for the protocol reference and a worked example.

### Diagnostics

#### `--debug-calibration`
*Introduced in v0.7.*

Off by default. When set, `bomdrift diff` writes one row to stderr per
finding it considers, with the schema:

```
kind|key|score|threshold
```

`kind` is one of `typosquat`, `version-jump`, `maintainer-age`, `cve`,
`recently-published`, `deprecated`, `maintainer-set-changed`. `key` is
a stable identifier (the package purl, advisory ID, etc.). `score` and
`threshold` are the numeric inputs to the gating decision.

The flag is purely diagnostic — it doesn't change which findings get
rendered. Pipe to a file:

```bash
bomdrift diff old.cdx.json new.cdx.json --debug-calibration 2> calibration.tsv
```

#### `--debug-calibration-format <FORMAT>`
*Introduced in v0.8.*

`pipe` (default, back-compat with v0.7) emits `kind|key|score|threshold`
per line; `jsonl` emits one JSON object per line for downstream tooling
that doesn't want to maintain a custom CSV-ish parser.

## `bomdrift init`
*Introduced in v0.6.*

Scaffold a copy-paste adoption setup in the current repository:

```bash
bomdrift init
```

Writes:

- `.bomdrift.toml`
- `.github/workflows/sbom-diff.yml`
- `.github/workflows/bomdrift-suppress.yml`

Flags:

- `--config-only` — write only `.bomdrift.toml`.
- `--force` — overwrite existing generated files. Without `--force`,
  existing files are preserved and the command fails loudly.

## `bomdrift baseline add`
*Introduced in v0.5; `--expires`/`--reason` v0.8; `--from-comment` v0.9.*

Append an advisory ID to a baseline file's `suppressed_advisories` list.
The file is created if missing; existing fields are preserved. Idempotent
(re-adding an existing ID is a no-op).

```bash
bomdrift baseline add GHSA-xxxx-yyyy-zzzz
bomdrift baseline add CVE-2026-12345 --path custom/baseline.json
bomdrift baseline add GHSA-evil-1234 \
    --expires 2026-12-31 \
    --reason "Awaiting upstream patch (issue #42)"
```

### Flags

- `<ID>` — advisory identifier (GHSA/CVE/MAL/OSV). Optional when
  `--from-comment` is supplied.
- `--path <PATH>` — baseline file path. Default
  `.bomdrift/baseline.json`.
- `--expires <YYYY-MM-DD>` — strict-format expiry; bomdrift refuses
  malformed dates (no silent never-expiring entries).
- `--reason <TEXT>` — free-form rationale; surfaces in VEX exports +
  expiry warnings.
- `--from-comment <BODY>` — parse a `/bomdrift suppress <ID> [reason: ...]`
  directive from a forge-issued comment body. Used by the GitLab /
  Bitbucket / Azure DevOps comment-bridge Workers. Exits non-zero on
  no-match so a webhook never silently no-ops.

## `bomdrift refresh-typosquat`
*Introduced in v0.4.*

Refresh the bundled typosquat top-package lists from upstream sources.

```bash
bomdrift refresh-typosquat                     # all wired-up ecosystems
bomdrift refresh-typosquat --ecosystem pypi    # one specific list
```

#### `--ecosystem <ECOSYSTEM>`

Which ecosystem's list to refresh. One of `all` (default), `npm`,
`pypi`, `cargo`, `nuget`, `maven`, `go`, `gem`, `composer`. The first
four fetch from canonical upstream feeds; the remaining four are
curated `data/<eco>-top*.txt` snapshots and `--ecosystem <name>` for
those emits a notice rather than fetching.

Refreshed lists are written to
`<XDG_CACHE_HOME>/bomdrift/typosquat/<eco>.txt` via temp-file + atomic
rename. The typosquat enricher prefers cache files over the embedded
snapshot when present and parseable.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success. |
| 1 | bomdrift internal error (parse failure, network mishap not gated by best-effort path, etc.). |
| 2 | `--fail-on` threshold or diff budget tripped. The body is still on stdout — the action posts it before propagating the exit code. |
| (clap 2) | Usage error from clap (unknown flag, missing required argument). Distinguishable from `--fail-on`-driven exit 2 by stderr containing `error: ...` rather than the rendered body. |

## Environment variables

| Variable | Purpose | Introduced |
|---|---|---|
| `GITHUB_TOKEN` | Bumps the GitHub REST rate limit from 60/hr unauth to 5000/hr authenticated, used by the maintainer-age enricher. | v0.2 |
| `BOMDRIFT_REPO_URL` | Fallback for `--repo-url` when the flag isn't passed. | v0.5 |
| `GITLAB_CI` | When `true`, auto-selects `--platform gitlab` (unless overridden). | v0.7 |
| `BITBUCKET_BUILD_NUMBER` | When set, auto-selects `--platform bitbucket`. | v0.9 |
| `TF_BUILD` | When set, auto-selects `--platform azure-devops`. | v0.9 |
| `CI_PROJECT_URL` | On GitLab CI, used as a final fallback for `--repo-url` after `BOMDRIFT_REPO_URL`. | v0.7 |
| `XDG_CACHE_HOME` | Cache root for OSV / EPSS / KEV / registry caches and refreshed typosquat lists. Defaults to `~/.cache` on Linux. | v0.1 |
| `SOURCE_DATE_EPOCH` | When set, used as "now" for byte-deterministic output (baseline-expiry comparisons, VEX timestamps, etc.). | v0.9 |
| `NO_COLOR` | Honored by the terminal renderer. | v0.1 |
| `CLICOLOR_FORCE` | Forces ANSI even on a non-TTY. | v0.1 |
| `BOMDRIFT_DEBUG` | When `1`, enables verbose stderr notes from best-effort enrichers. | v0.8 |
