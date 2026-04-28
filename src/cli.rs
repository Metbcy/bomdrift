use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

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
    /// Which ecosystem's list to refresh. Defaults to `all`. v0 only
    /// implements `npm`; PyPI/Cargo/Maven will land in a follow-up release
    /// (the value is accepted today and will start fetching transparently
    /// once the per-ecosystem source URLs are wired up).
    #[arg(long, value_enum, default_value_t = RefreshEcosystem::All)]
    pub ecosystem: RefreshEcosystem,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefreshEcosystem {
    /// Refresh every ecosystem with a wired-up fetcher (currently: npm only).
    All,
    /// Refresh just the npm top-1000 list from the anvaka most-depended-upon gist.
    Npm,
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
