pub mod cli;
pub mod diff;
pub mod enrich;
pub mod model;
pub mod parse;
pub mod render;

use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};

use crate::cli::{Cli, Command, DiffArgs, OutputFormat};

pub fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Diff(args) => run_diff(args),
        Command::RefreshTyposquat => {
            bail!("`refresh-typosquat` is not implemented yet (planned for v0.2)")
        }
    }
}

fn run_diff(args: DiffArgs) -> Result<()> {
    let before = load_sbom(&args.before)?;
    let after = load_sbom(&args.after)?;

    let cs = diff::diff(&before, &after);

    let enrichment = if args.no_osv {
        enrich::Enrichment::default()
    } else {
        // OSV enrichment is best-effort. Network failures must not block the diff
        // from rendering — a PR review is still useful without CVE data.
        match enrich::osv::enrich(&cs) {
            Ok(e) => e,
            Err(err) => {
                eprintln!("warning: OSV enrichment failed, continuing without it: {err:#}");
                enrich::Enrichment::default()
            }
        }
    };

    let rendered = match args.output {
        OutputFormat::Terminal | OutputFormat::Markdown => {
            render::markdown::render(&cs, &enrichment)
        }
        OutputFormat::Json => bail!("--output json is not implemented yet (planned for v0.2)"),
        OutputFormat::Sarif => bail!("--output sarif is not implemented yet (planned for v0.2)"),
    };

    print!("{rendered}");
    Ok(())
}

fn load_sbom(path: &Path) -> Result<model::Sbom> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("reading SBOM file: {}", path.display()))?;
    let value: serde_json::Value = serde_json::from_str(&raw)
        .with_context(|| format!("parsing JSON in: {}", path.display()))?;
    parse::parse(value).with_context(|| format!("normalizing SBOM from: {}", path.display()))
}
