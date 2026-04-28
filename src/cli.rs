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
    RefreshTyposquat,
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
