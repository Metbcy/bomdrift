use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

use crate::model::SbomFormat;

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
    Diff(DiffArgs),
    /// Refresh the bundled typosquat top-package lists from upstream sources.
    ///
    /// Writes a fresh per-ecosystem list to the user's XDG cache directory
    /// (`<XDG_CACHE_HOME>/bomdrift/typosquat/<ecosystem>.txt` on Linux). The
    /// typosquat enricher will pick up the cache file in subsequent runs,
    /// overlaying the snapshot baked into the binary at compile time.
    RefreshTyposquat(RefreshArgs),
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
    /// Refresh every ecosystem with a wired-up fetcher (npm, PyPI, Cargo).
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
}

#[derive(Args, Debug)]
pub struct DiffArgs {
    /// Path to the "before" SBOM (CycloneDX, SPDX, or Syft JSON).
    pub before: PathBuf,
    /// Path to the "after" SBOM (CycloneDX, SPDX, or Syft JSON).
    pub after: PathBuf,
    /// Output format.
    #[arg(long, value_enum, default_value_t = OutputFormat::Terminal)]
    pub output: OutputFormat,
    /// Force input format detection.
    #[arg(long, value_enum, default_value_t = InputFormat::Auto)]
    pub format: InputFormat,
    /// Skip OSV.dev CVE enrichment (offline mode, faster, deterministic).
    #[arg(long)]
    pub no_osv: bool,
    /// Skip the maintainer-age enricher (no GitHub API calls). Use for offline
    /// runs and tests; required when `GITHUB_TOKEN` is unset and the unauth
    /// rate limit (60/hr) is too low for the diff being analyzed.
    #[arg(long)]
    pub no_maintainer_age: bool,
    /// Exit with code 2 when findings of the configured severity or higher
    /// surface. Default `none` is informational-only (always exit 0 on a
    /// successful run).
    #[arg(long, value_enum, default_value_t = FailOn::None)]
    pub fail_on: FailOn,
}

/// Threshold for `--fail-on` exit-code-2 behavior.
///
/// Variants are intentionally ordered loosest-to-strictest in their
/// declaration order, but the comparison logic in [`crate::tripped`] is
/// per-variant rather than ordinal — adding a new variant later is safe.
#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
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
    /// Trip on ANY finding (CVE, typosquat, version-jump, young-maintainer)
    /// OR any license-changed-without-version-bump pair (the suspicious case).
    Any,
}

#[derive(ValueEnum, Clone, Copy, Debug)]
pub enum OutputFormat {
    Terminal,
    Markdown,
    Json,
    Sarif,
}

#[derive(ValueEnum, Clone, Copy, Debug)]
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
