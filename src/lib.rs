pub mod cli;
pub mod diff;
pub mod enrich;
pub mod model;
pub mod parse;
pub mod refresh;
pub mod render;

use std::fs;
use std::io::IsTerminal;
use std::path::Path;

use anyhow::{Context, Result};

use crate::cli::{Cli, Command, DiffArgs, FailOn, OutputFormat};
use crate::diff::ChangeSet;
use crate::enrich::Enrichment;

/// Process exit code emitted when `--fail-on` trips. Distinct from clap's
/// usage-error exit (`2`-ish on parse failure) because clap exits before
/// `run` is called — there's no overlap window where this code is ambiguous.
pub const FAIL_ON_EXIT_CODE: i32 = 2;

pub fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Diff(args) => run_diff(args),
        Command::RefreshTyposquat(args) => refresh::run(args),
    }
}

fn run_diff(args: DiffArgs) -> Result<()> {
    let format_hint = args.format.to_sbom_format();
    let before = load_sbom(&args.before, format_hint)?;
    let after = load_sbom(&args.after, format_hint)?;

    let cs = diff::diff(&before, &after);

    let mut enrichment = if args.no_osv {
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

    // Typosquat detection is pure-compute (embedded reference list) and always
    // runs, regardless of `--no-osv`. Findings are informational.
    enrichment.typosquats = enrich::typosquat::enrich(&cs);

    // Multi-major version-jump detection is pure-compute and also always runs.
    // Findings are informational.
    enrichment.version_jumps = enrich::version_jump::enrich(&cs);

    // Maintainer-age enrichment hits the GitHub REST API; gated behind
    // `--no-maintainer-age` for offline runs. Best-effort: failures warn and
    // continue, mirroring the OSV enricher's contract.
    if !args.no_maintainer_age {
        match enrich::maintainer::enrich(&cs) {
            Ok(findings) => enrichment.maintainer_age = findings,
            Err(err) => {
                eprintln!(
                    "warning: maintainer-age enrichment failed, continuing without it: {err:#}"
                );
            }
        }
    }

    let rendered = match args.output {
        OutputFormat::Terminal => {
            // ANSI escapes are only safe on a real TTY. Piped/redirected stdout
            // (e.g. captured by a CI step that posts a PR comment) must stay
            // plain markdown so it renders correctly in a comment body.
            if std::io::stdout().is_terminal() {
                render::term::render(&cs, &enrichment)
            } else {
                render::markdown::render(&cs, &enrichment)
            }
        }
        OutputFormat::Markdown => render::markdown::render(&cs, &enrichment),
        OutputFormat::Json => render::json::render(&cs, &enrichment),
        OutputFormat::Sarif => render::sarif::render(&cs, &enrichment),
    };

    print!("{rendered}");

    // Body must be fully written before we exit-2 — the action's `tee`
    // wrapper still wants the comment posted even when fail-on trips.
    if tripped(&cs, &enrichment, args.fail_on) {
        if matches!(args.fail_on, FailOn::CriticalCve) {
            eprintln!(
                "warning: --fail-on=critical-cve is treated as --fail-on=cve in v0.2 \
                 because OSV's /v1/querybatch does not return severity. v0.3 will \
                 narrow this to CVSS >= 9.0."
            );
        }
        std::process::exit(FAIL_ON_EXIT_CODE);
    }

    Ok(())
}

/// Pure helper: does this `(changeset, enrichment)` pair trip the configured
/// fail-on threshold? Side-effect-free so the policy is easy to unit-test
/// without spinning up the full pipeline.
pub fn tripped(cs: &ChangeSet, e: &Enrichment, threshold: FailOn) -> bool {
    match threshold {
        FailOn::None => false,
        // CriticalCve is treated as Cve in v0.2 (see DiffArgs.fail_on doc
        // comment for rationale); the diagnostic warning is emitted at the
        // `run_diff` exit path, not here, to keep `tripped` pure.
        FailOn::Cve | FailOn::CriticalCve => !e.vulns.is_empty(),
        FailOn::Typosquat => !e.typosquats.is_empty(),
        FailOn::Any => e.has_findings() || !cs.license_changed.is_empty(),
    }
}

fn load_sbom(path: &Path, format_hint: Option<model::SbomFormat>) -> Result<model::Sbom> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("reading SBOM file: {}", path.display()))?;
    let value: serde_json::Value = serde_json::from_str(&raw)
        .with_context(|| format!("parsing JSON in: {}", path.display()))?;
    parse::parse_with_format(value, format_hint)
        .with_context(|| format!("normalizing SBOM from: {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    use crate::enrich::typosquat::TyposquatFinding;
    use crate::enrich::version_jump::VersionJumpFinding;
    use crate::model::{Component, Ecosystem, Relationship};

    fn comp(name: &str) -> Component {
        Component {
            name: name.to_string(),
            version: "1.0.0".to_string(),
            ecosystem: Ecosystem::Npm,
            purl: Some(format!("pkg:npm/{name}@1.0.0")),
            licenses: Vec::new(),
            supplier: None,
            hashes: Vec::new(),
            relationship: Relationship::Unknown,
            source_url: None,
            bom_ref: None,
        }
    }

    fn enrichment_with_cve() -> Enrichment {
        let mut vulns: HashMap<String, Vec<String>> = HashMap::new();
        vulns.insert("pkg:npm/foo@1.0.0".into(), vec!["CVE-2025-1".into()]);
        Enrichment {
            vulns,
            ..Default::default()
        }
    }

    fn enrichment_with_typosquat() -> Enrichment {
        Enrichment {
            typosquats: vec![TyposquatFinding {
                component: comp("plain-crypto-js"),
                closest: "crypto-js".to_string(),
                score: 0.95,
            }],
            ..Default::default()
        }
    }

    fn enrichment_with_version_jump() -> Enrichment {
        Enrichment {
            version_jumps: vec![VersionJumpFinding {
                before: comp("foo"),
                after: comp("foo"),
                before_major: 1,
                after_major: 4,
            }],
            ..Default::default()
        }
    }

    fn cs_with_license_change() -> ChangeSet {
        let mut before = comp("foo");
        before.licenses = vec!["MIT".into()];
        let mut after = comp("foo");
        after.licenses = vec!["GPL-3.0".into()];
        ChangeSet {
            license_changed: vec![(before, after)],
            ..Default::default()
        }
    }

    #[test]
    fn fail_on_none_never_trips() {
        assert!(!tripped(
            &ChangeSet::default(),
            &Enrichment::default(),
            FailOn::None
        ));
        assert!(!tripped(
            &cs_with_license_change(),
            &enrichment_with_cve(),
            FailOn::None
        ));
    }

    #[test]
    fn fail_on_cve_trips_only_on_cve_findings() {
        assert!(tripped(
            &ChangeSet::default(),
            &enrichment_with_cve(),
            FailOn::Cve
        ));
        assert!(!tripped(
            &ChangeSet::default(),
            &enrichment_with_typosquat(),
            FailOn::Cve
        ));
        assert!(!tripped(
            &ChangeSet::default(),
            &Enrichment::default(),
            FailOn::Cve
        ));
    }

    #[test]
    fn fail_on_critical_cve_currently_aliases_to_cve() {
        // Documented v0.2 behavior: severity isn't populated yet from OSV's
        // /v1/querybatch, so critical-cve currently fires on any CVE. The
        // user-facing warning is emitted at the run_diff exit, not here.
        assert!(tripped(
            &ChangeSet::default(),
            &enrichment_with_cve(),
            FailOn::CriticalCve
        ));
    }

    #[test]
    fn fail_on_typosquat_trips_only_on_typosquat_findings() {
        assert!(tripped(
            &ChangeSet::default(),
            &enrichment_with_typosquat(),
            FailOn::Typosquat
        ));
        assert!(!tripped(
            &ChangeSet::default(),
            &enrichment_with_cve(),
            FailOn::Typosquat
        ));
    }

    #[test]
    fn fail_on_any_trips_on_each_finding_kind_and_license_changes() {
        assert!(tripped(
            &ChangeSet::default(),
            &enrichment_with_cve(),
            FailOn::Any
        ));
        assert!(tripped(
            &ChangeSet::default(),
            &enrichment_with_typosquat(),
            FailOn::Any
        ));
        assert!(tripped(
            &ChangeSet::default(),
            &enrichment_with_version_jump(),
            FailOn::Any
        ));
        // license-changed-without-version-bump alone trips Any (the suspicious
        // case lives on the ChangeSet, not the enrichment).
        assert!(tripped(
            &cs_with_license_change(),
            &Enrichment::default(),
            FailOn::Any
        ));
        assert!(!tripped(
            &ChangeSet::default(),
            &Enrichment::default(),
            FailOn::Any
        ));
    }

    #[test]
    fn fail_on_typosquat_ignores_license_change() {
        // license_changed is a ChangeSet field, not an enrichment. The
        // typosquat threshold is strictly about typosquat findings — license
        // drift must NOT trip it (otherwise consumers using --fail-on=typosquat
        // get unexpected exit-2's on every license correction).
        assert!(!tripped(
            &cs_with_license_change(),
            &Enrichment::default(),
            FailOn::Typosquat
        ));
    }
}
