use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};
use serde::Deserialize;

use crate::model::SbomFormat;
use crate::render::markdown;

#[derive(Parser, Debug)]
#[command(
    name = "bomdrift",
    version,
    about = "SBOM diff with supply-chain risk signals.",
    long_about = None,
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Diff two SBOMs and surface supply-chain risk signals on changed components.
    Diff(Box<DiffArgs>),
    /// Refresh the bundled typosquat top-package lists from upstream sources.
    ///
    /// Writes a fresh per-ecosystem list to the user's XDG cache directory
    /// (`<XDG_CACHE_HOME>/bomdrift/typosquat/<ecosystem>.txt` on Linux). The
    /// typosquat enricher will pick up the cache file in subsequent runs,
    /// overlaying the snapshot baked into the binary at compile time.
    RefreshTyposquat(RefreshArgs),
    /// Manage the suppression baseline file (v0.5+).
    ///
    /// The comment-suppress sub-action invokes `bomdrift baseline add <id>`
    /// when a reviewer comments `/bomdrift suppress <id>` on a PR; the
    /// subcommand is also useful from the command line for hand-curating a
    /// baseline without editing JSON directly.
    Baseline {
        #[command(subcommand)]
        action: BaselineAction,
    },
    /// Scaffold bomdrift config and GitHub Actions workflows in this repo.
    Init(InitArgs),
}

#[derive(Args, Debug)]
pub struct InitArgs {
    /// Overwrite existing generated files.
    #[arg(long)]
    pub force: bool,

    /// Only write `.bomdrift.toml`; skip GitHub workflow files.
    #[arg(long)]
    pub config_only: bool,
}

#[derive(Subcommand, Debug)]
pub enum BaselineAction {
    /// Append an advisory ID to the baseline's `suppressed_advisories` list.
    /// The file is created if it doesn't exist; existing fields are preserved.
    /// Idempotent — re-adding an existing ID is a no-op (exit 0).
    Add(BaselineAddArgs),
}

#[derive(Args, Debug)]
pub struct BaselineAddArgs {
    /// Advisory identifier to suppress (GHSA-..., CVE-..., MAL-...). Suppresses
    /// the advisory across ALL components in subsequent diffs — a wildcard
    /// match by ID. Use the diff-output baseline format (the JSON shape
    /// emitted by `bomdrift diff --output json`) for finer per-purl
    /// suppression instead.
    ///
    /// Optional when `--from-comment` is supplied — the directive in
    /// the comment body provides the ID instead.
    pub id: Option<String>,

    /// Path to the baseline file. Created if missing; parent directory is
    /// created if missing.
    #[arg(long, default_value = ".bomdrift/baseline.json")]
    pub path: PathBuf,

    /// Optional expiry date (YYYY-MM-DD). Once today is past this date,
    /// the entry stops suppressing and bomdrift prints a warning to
    /// stderr. Useful for time-boxed risk acceptance ("ignore until
    /// upstream ships a fix"). Strict format: zero-padded month/day.
    #[arg(long)]
    pub expires: Option<String>,

    /// Optional human-readable reason recorded alongside the entry.
    /// Surfaces in the v0.9 VEX export and in the warning printed when
    /// the entry expires. Free-form text.
    #[arg(long)]
    pub reason: Option<String>,

    /// Parse the body of a forge-issued PR/MR comment and extract the
    /// suppress directive. Accepts the raw note body as a single
    /// string. The directive grammar (matched case-sensitively at the
    /// start of any line, after optional leading whitespace):
    ///
    /// ```text
    /// /bomdrift suppress <ID>[ reason: <text>]
    /// ```
    ///
    /// `<ID>` must match `(?:GHSA|CVE|MAL|OSV)-[A-Z0-9-]+`. When no
    /// matching line is found, the command exits with a non-zero code
    /// and prints a clear stderr message — so a webhook bridge that
    /// invokes this flag doesn't silently no-op on a non-suppress
    /// comment. v0.9+.
    #[arg(long)]
    pub from_comment: Option<String>,
}

#[derive(Args, Debug)]
pub struct RefreshArgs {
    /// Which ecosystem's list to refresh. Defaults to `all`.
    ///
    /// `npm`, `pypi`, and `cargo` fetch fresh top-package lists from their
    /// canonical upstream sources (anvaka gist, hugovk JSON, crates.io API).
    /// `maven` is hand-curated — there is no canonical "top N" feed for
    /// Maven Central, so the embedded list is the source of truth and
    /// `--ecosystem maven` emits a notice rather than fetching anything.
    #[arg(long, value_enum, default_value_t = RefreshEcosystem::All)]
    pub ecosystem: RefreshEcosystem,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefreshEcosystem {
    /// Refresh every ecosystem with a wired-up fetcher (npm, PyPI, Cargo, NuGet).
    All,
    /// Refresh just the npm top-1000 list from the anvaka most-depended-upon gist.
    Npm,
    /// Refresh the PyPI top-200 list from hugovk/top-pypi-packages.
    #[value(name = "pypi")]
    PyPI,
    /// Refresh the Cargo (crates.io) top-200 list from the crates.io API.
    Cargo,
    /// Maven has no canonical upstream feed; the list is curated and shipped
    /// embedded. This variant is accepted so `--ecosystem all` stays
    /// stable, and emits an informational notice.
    Maven,
    /// Go has no canonical upstream popularity feed; the list is curated
    /// from pkg.go.dev and well-known imports. Variant is accepted so
    /// `--ecosystem all` stays stable, and emits an informational notice.
    Go,
    /// RubyGems' public most-downloaded API has gone through several
    /// breaking changes; the v0.4 list is curated. Variant is accepted
    /// so `--ecosystem all` stays stable, and emits an informational
    /// notice.
    Gem,
    /// Refresh the NuGet top-200 list from the nuget.org v3 search API.
    #[value(name = "nuget")]
    NuGet,
    /// Packagist's public statistics API has gone through several
    /// breaking changes; the v0.4 Composer list is curated. Variant is
    /// accepted so `--ecosystem all` stays stable, and emits an
    /// informational notice.
    Composer,
}

/// Forge the rendered markdown is destined for. Drives the action-affordance
/// footer in `render::markdown` and CI-side defaults (e.g. detection of
/// `GITLAB_CI` / `CI_PROJECT_URL`).
///
/// Variants intentionally cover only forges with a wired-up footer
/// implementation. New forges (Bitbucket, Gitea, ...) are an additive change.
#[derive(ValueEnum, Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Platform {
    /// GitHub.com or GitHub Enterprise. Default — preserves the v0.5
    /// footer shape for existing consumers.
    #[default]
    #[value(name = "github")]
    GitHub,
    /// GitLab.com or Self-Managed GitLab. The MR-note footer omits the
    /// `/bomdrift suppress` hint and points at `bomdrift baseline add`
    /// instead, because GitLab in-comment suppression is deferred to
    /// v0.8 (note webhooks have a different model than GitHub PR
    /// comments).
    #[value(name = "gitlab")]
    GitLab,
    /// Bitbucket Cloud or Bitbucket Data Center. Footer points
    /// reviewers at the `/issues/new` form and uses `bomdrift baseline
    /// add <ID>` for suppression — Bitbucket has no in-comment
    /// suppression flow in v0.9.
    #[value(name = "bitbucket")]
    Bitbucket,
    /// Azure DevOps Repos (Azure Pipelines). Footer points reviewers at
    /// the work-item create form and uses `bomdrift baseline add <ID>`
    /// for suppression.
    #[value(name = "azure-devops")]
    AzureDevOps,
}

impl From<Platform> for markdown::Platform {
    /// User-facing CLI / config enum maps 1:1 to the renderer's enum. The
    /// two are kept separate so the renderer doesn't take a clap+serde
    /// dependency, but the variants must stay in lockstep — the match
    /// here is exhaustive on purpose: a new variant added to one side
    /// fails the build on the other until both are updated.
    fn from(value: Platform) -> Self {
        match value {
            Platform::GitHub => markdown::Platform::GitHub,
            Platform::GitLab => markdown::Platform::GitLab,
            Platform::Bitbucket => markdown::Platform::Bitbucket,
            Platform::AzureDevOps => markdown::Platform::AzureDevOps,
        }
    }
}

#[derive(Args, Debug)]
pub struct DiffArgs {
    /// Path to the "before" SBOM (CycloneDX, SPDX, or Syft JSON).
    pub before: PathBuf,
    /// Path to the "after" SBOM (CycloneDX, SPDX, or Syft JSON).
    pub after: PathBuf,
    /// Path to a repo policy config file. When omitted, `.bomdrift.toml` is
    /// loaded if it exists in the current working directory.
    #[arg(long)]
    pub config: Option<PathBuf>,
    /// Output format (default: terminal, unless `.bomdrift.toml` sets one).
    #[arg(long, value_enum)]
    pub output: Option<OutputFormat>,
    /// Force input format detection (default: auto, unless `.bomdrift.toml`
    /// sets one).
    #[arg(long, value_enum)]
    pub format: Option<InputFormat>,
    /// Skip OSV.dev CVE enrichment (offline mode, faster, deterministic).
    #[arg(long)]
    pub no_osv: bool,
    /// Skip the on-disk OSV severity cache (`<XDG_CACHE_HOME>/bomdrift/osv/`).
    /// Useful for reproducibility audits and the rare case where a stale
    /// cached severity (within the 24-hour TTL) is actively misleading. Has
    /// no effect when `--no-osv` is set.
    #[arg(long)]
    pub no_osv_cache: bool,
    /// Path to a baseline JSON file (output of a previous `bomdrift diff
    /// --output json` run). Findings present in the baseline are suppressed
    /// from this run's output; only what *changed* surfaces. Lets a team
    /// adopt bomdrift on a project with pre-existing findings without
    /// drowning the first PR comment.
    #[arg(long)]
    pub baseline: Option<PathBuf>,
    /// Skip the maintainer-age enricher (no GitHub API calls). Use for offline
    /// runs and tests; required when `GITHUB_TOKEN` is unset and the unauth
    /// rate limit (60/hr) is too low for the diff being analyzed.
    #[arg(long)]
    pub no_maintainer_age: bool,
    /// Exit with code 2 when findings of the configured severity or higher
    /// surface (default: none, unless `.bomdrift.toml` sets one).
    #[arg(long, value_enum)]
    pub fail_on: Option<FailOn>,
    /// Emit only the summary table (counts per change/finding category) and
    /// a footer pointing at the full output, omitting every per-category
    /// section. The PR-comment-friendly form for diffs that would otherwise
    /// blow past GitHub's 65,536-character comment-body cap.
    ///
    /// Markdown-only: terminal / JSON / SARIF outputs ignore the flag (the
    /// goal is comment-size compression, not data loss).
    #[arg(long)]
    pub summary_only: bool,
    /// Markdown-only. Omit raw Added / Removed / Version changed detail
    /// sections, leaving the summary table plus risk-bearing sections. Useful
    /// for PR comments where reviewers only want actionable findings.
    #[arg(long)]
    pub findings_only: bool,
    /// Keep `Ecosystem::Other("file")` pseudo-components emitted by Syft's
    /// directory cataloger. Off by default — the cataloger emits each
    /// YAML / lockfile / source file in the scanned directory as a synthetic
    /// component whose path differs between the PR-head and base-ref
    /// checkouts, producing phantom Added/Removed pairs that drown real
    /// package changes. Enable for debugging or auditing the raw cataloger
    /// output.
    #[arg(long)]
    pub include_file_components: bool,
    /// Repository URL (e.g. `https://github.com/owner/repo`) used to
    /// render the markdown comment's action-affordance footer — the
    /// "Report this finding" link target and the suppress-comment hint.
    /// When unset, falls back to the `BOMDRIFT_REPO_URL` env var; when
    /// neither is set, the footer is omitted so forks and standalone CLI
    /// use don't render dead links to bomdrift's own issue tracker.
    #[arg(long)]
    pub repo_url: Option<String>,
    /// Forge the rendered markdown is destined for. Controls the action-
    /// affordance footer shape (GitHub uses the `/bomdrift suppress`
    /// comment-driven flow; GitLab points reviewers at the manual
    /// `bomdrift baseline add` CLI flow). When omitted, auto-detects from
    /// CI environment variables (`GITLAB_CI=true` → GitLab; default
    /// otherwise is GitHub).
    #[arg(long, value_enum)]
    pub platform: Option<Platform>,
    /// Exit 2 when more than this many components are added in one diff.
    #[arg(long)]
    pub max_added: Option<usize>,
    /// Exit 2 when more than this many components are removed in one diff.
    #[arg(long)]
    pub max_removed: Option<usize>,
    /// Exit 2 when more than this many components change version in one diff.
    #[arg(long)]
    pub max_version_changed: Option<usize>,
    /// Print one CSV-friendly stderr line per finding showing the score
    /// and the threshold that gated it. Off by default. Used to gather
    /// real-world calibration data — `SIMILARITY_THRESHOLD` for
    /// typosquats, `YOUNG_MAINTAINER_DAYS` for maintainer-age — without
    /// shipping telemetry. The output is opt-in and the user owns the
    /// resulting CSV; pipe to a file with `2>calibration.csv`.
    ///
    /// Format: `kind|key|score|threshold` per line. `kind` is one of
    /// `typosquat`, `maintainer-age`, `version-jump`, `cve`. `score` is
    /// the underlying similarity / age / jump-size / CVSS value;
    /// `threshold` is the constant the finding was compared against.
    /// Skip the EPSS enricher (FIRST.org) entirely. Useful for offline /
    /// air-gapped CI where outbound HTTP is blocked, or when EPSS data is
    /// not part of the team's risk model. Disables both the network call
    /// and the disk cache lookup.
    #[arg(long)]
    pub no_epss: bool,
    /// Skip the CISA KEV enricher entirely.
    #[arg(long)]
    pub no_kev: bool,
    /// Trip exit-2 when any advisory's EPSS score is >= this threshold
    /// (0.0 - 1.0). Recommended starting point: 0.5 (top decile of
    /// actively-exploited CVEs). Implicit `--fail-on cve` semantics —
    /// only advisories surface this; non-CVE findings are unaffected.
    #[arg(long)]
    pub fail_on_epss: Option<f32>,
    /// Comma-separated SPDX license identifiers (or `*`-suffix globs)
    /// permitted by policy. May be repeated. CLI flag takes precedence
    /// over `[license] allow` in `.bomdrift.toml` (override, not merge).
    #[arg(long, value_delimiter = ',')]
    pub allow_licenses: Vec<String>,
    /// Comma-separated SPDX license identifiers (or `*`-suffix globs)
    /// forbidden by policy. May be repeated. Deny wins when a license
    /// matches both allow and deny.
    #[arg(long, value_delimiter = ',')]
    pub deny_licenses: Vec<String>,
    /// When set, compound SPDX expressions like `(MIT OR GPL-3.0)` are
    /// permitted (the v0.9 SPDX evaluator will replace this with proper
    /// expression evaluation). Off by default — fail-closed.
    #[arg(long)]
    pub allow_ambiguous_licenses: bool,
    /// Path(s) to VEX (Vulnerability Exploitability eXchange) files
    /// to consume. Repeatable. Each file is auto-detected as either
    /// OpenVEX 0.2.0 or CycloneDX VEX 1.6. Statements with status
    /// `not_affected` / `fixed` suppress matching findings; statements
    /// with `under_investigation` annotate without suppressing;
    /// statements with `affected` annotate as a no-op badge. See
    /// <https://metbcy.github.io/bomdrift/vex.html> for the
    /// finding-id matching rules including the synthetic-id convention
    /// for non-CVE findings.
    #[arg(long, action = clap::ArgAction::Append)]
    pub vex: Vec<PathBuf>,
    /// Emit a single OpenVEX 0.2.0 doc covering every finding in the
    /// post-baseline diff. Baseline-suppressed entries inherit their
    /// `vex_status` from the baseline entry (defaulting to
    /// `under_investigation` to avoid publishing false `not_affected`
    /// claims); un-suppressed findings emit as `affected`. v0.9+.
    #[arg(long)]
    pub emit_vex: Option<PathBuf>,
    /// Skip registry-metadata enrichers (npm/PyPI/crates.io) entirely.
    /// Use for offline runs or when you don't want bomdrift to fan out
    /// HTTP requests to package registries.
    #[arg(long)]
    pub no_registry: bool,
    /// Recently-published threshold in days. Components published
    /// within this window trip a `RecentlyPublished` finding. Default
    /// 14 days; set to 0 to disable the kind without disabling the
    /// other registry checks.
    #[arg(long)]
    pub recently_published_days: Option<i64>,
    /// VEX `author` for `--emit-vex`. Falls back to repo_url, then
    /// to `"bomdrift"`. v0.9+.
    #[arg(long)]
    pub vex_author: Option<String>,
    /// Default OpenVEX `justification` written into emitted statements
    /// when the source baseline entry doesn't supply one. Defaults to
    /// `"vulnerable_code_not_in_execute_path"` — the safe fallback per
    /// the OpenVEX spec.
    #[arg(long)]
    pub vex_default_justification: Option<String>,
    #[arg(long)]
    pub debug_calibration: bool,
    /// Format for `--debug-calibration` rows. `pipe` (default, back-compat
    /// with v0.7) emits `kind|key|score|threshold` per line; `jsonl` emits
    /// one JSON object per line for downstream tooling that doesn't want
    /// to maintain a custom CSV-ish parser.
    #[arg(long, value_enum, default_value_t = DebugFormat::Pipe)]
    pub debug_calibration_format: DebugFormat,
    /// Write the chosen `--output` format to this path instead of stdout.
    /// Useful for SARIF (`--output sarif --output-file bomdrift.sarif`)
    /// where YAML quoting `>` redirection is fragile in CI templates.
    #[arg(long)]
    pub output_file: Option<PathBuf>,
}

/// Wire format for `--debug-calibration` output. Pipe-delimited keeps v0.7
/// callers working unchanged; JSONL is the recommended shape for new tooling
/// because adding a new finding kind doesn't fork the parser.
#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DebugFormat {
    #[default]
    Pipe,
    Jsonl,
}

/// Threshold for `--fail-on` exit-code-2 behavior.
///
/// Variants are intentionally ordered loosest-to-strictest in their
/// declaration order, but the comparison logic in [`crate::tripped`] is
/// per-variant rather than ordinal — adding a new variant later is safe.
#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FailOn {
    /// Never trip. Default. The diff is informational-only.
    None,
    /// Trip when at least one CVE / advisory finding is present in
    /// `enrichment.vulns`.
    Cve,
    /// Trip only when an advisory at severity HIGH or above is present
    /// (per OSV's `database_specific.severity` GHSA label, fetched via
    /// `/v1/vulns/{id}`). Advisories with no resolvable severity surface
    /// in the diff but do NOT trip this threshold.
    CriticalCve,
    /// Trip when at least one typosquat finding is present.
    Typosquat,
    /// Trip when at least one same-version license change is present.
    LicenseChange,
    /// Trip when any advisory's CISA KEV flag is set (i.e. listed in the
    /// Known Exploited Vulnerabilities catalog). KEV is a high-signal
    /// "actively exploited in the wild" claim — narrower than `cve` but
    /// less rigid than `critical-cve` (KEV entries can be Medium-severity).
    Kev,
    /// Trip on a license-policy violation (Phase D, v0.8+).
    LicenseViolation,
    /// Trip when a registry-metadata enricher (npm/PyPI/crates.io) flags
    /// any added component as published within the
    /// recently-published threshold (default 14 days). v0.9+.
    RecentlyPublished,
    /// Trip when a registry-metadata enricher flags any component as
    /// deprecated or yanked upstream. v0.9+.
    Deprecated,
    /// Trip on ANY finding (CVE, typosquat, version-jump, young-maintainer)
    /// OR any license-changed-without-version-bump pair (the suspicious case).
    Any,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OutputFormat {
    Terminal,
    Markdown,
    Json,
    Sarif,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum InputFormat {
    Auto,
    Cdx,
    Spdx,
    Syft,
}

impl InputFormat {
    /// Convert the user-facing `--format` flag to the internal model enum used
    /// by the parser layer. `Auto` returns `None`, signalling auto-detection;
    /// every other variant maps 1:1 to a forced-parse hint.
    pub fn to_sbom_format(self) -> Option<SbomFormat> {
        match self {
            InputFormat::Auto => None,
            InputFormat::Cdx => Some(SbomFormat::CycloneDx),
            InputFormat::Spdx => Some(SbomFormat::Spdx),
            InputFormat::Syft => Some(SbomFormat::Syft),
        }
    }
}
