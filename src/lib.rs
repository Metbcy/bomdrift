pub mod baseline;
pub mod cli;
pub mod config;
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

use crate::cli::{BaselineAction, Cli, Command, DiffArgs, FailOn, InitArgs, OutputFormat};
use crate::diff::ChangeSet;
use crate::enrich::{Enrichment, Severity};

/// Process exit code emitted when `--fail-on` trips. Distinct from clap's
/// usage-error exit (`2`-ish on parse failure) because clap exits before
/// `run` is called — there's no overlap window where this code is ambiguous.
pub const FAIL_ON_EXIT_CODE: i32 = 2;

pub fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Diff(args) => run_diff(args),
        Command::RefreshTyposquat(args) => refresh::run(args),
        Command::Baseline { action } => run_baseline(action),
        Command::Init(args) => run_init(args),
    }
}

fn run_init(args: InitArgs) -> Result<()> {
    write_scaffold_file(Path::new(".bomdrift.toml"), INIT_CONFIG, args.force)?;
    if !args.config_only {
        write_scaffold_file(
            Path::new(".github/workflows/sbom-diff.yml"),
            INIT_SBOM_WORKFLOW,
            args.force,
        )?;
        write_scaffold_file(
            Path::new(".github/workflows/bomdrift-suppress.yml"),
            INIT_SUPPRESS_WORKFLOW,
            args.force,
        )?;
    }
    eprintln!("bomdrift: initialized repository files");
    Ok(())
}

fn write_scaffold_file(path: &Path, contents: &str, force: bool) -> Result<()> {
    if path.exists() && !force {
        anyhow::bail!(
            "{} already exists; re-run with --force to overwrite",
            path.display()
        );
    }
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent)
            .with_context(|| format!("creating parent directory: {}", parent.display()))?;
    }
    fs::write(path, contents).with_context(|| format!("writing scaffold file: {}", path.display()))
}

fn run_baseline(action: BaselineAction) -> Result<()> {
    match action {
        BaselineAction::Add(args) => {
            let outcome = baseline::add_suppression(&args.path, &args.id)?;
            match outcome {
                baseline::AddOutcome::Added => {
                    eprintln!(
                        "bomdrift: added '{id}' to {path}",
                        id = args.id.trim(),
                        path = args.path.display(),
                    );
                }
                baseline::AddOutcome::AlreadyPresent => {
                    eprintln!(
                        "bomdrift: '{id}' already present in {path}; no change",
                        id = args.id.trim(),
                        path = args.path.display(),
                    );
                }
            }
            Ok(())
        }
    }
}

fn run_diff(mut args: DiffArgs) -> Result<()> {
    config::apply_diff_config(&mut args)?;

    let output = args.output.unwrap_or(OutputFormat::Terminal);
    let format = args.format.unwrap_or(cli::InputFormat::Auto);
    let fail_on = args.fail_on.unwrap_or(FailOn::None);

    let format_hint = format.to_sbom_format();
    let before = load_sbom(&args.before, format_hint, args.include_file_components)?;
    let after = load_sbom(&args.after, format_hint, args.include_file_components)?;

    let mut cs = diff::diff(&before, &after);

    let mut enrichment = if args.no_osv {
        enrich::Enrichment::default()
    } else {
        // OSV enrichment is best-effort. Network failures must not block the diff
        // from rendering — a PR review is still useful without CVE data.
        match enrich::osv::enrich_cached(&cs, args.no_osv_cache) {
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

    // Apply the baseline AFTER all enrichers run — suppression operates on
    // the realized finding set, not on intermediate inputs. This keeps the
    // baseline file format stable as new enrichers are added: a new finding
    // type that the baseline doesn't know about simply isn't suppressed.
    if let Some(path) = &args.baseline {
        let baseline = baseline::Baseline::load(path)?;
        baseline::apply(&mut cs, &mut enrichment, &baseline);
    }

    // Calibration tap. Off by default; opt-in via `--debug-calibration`.
    // Emits one CSV-friendly line per finding to stderr so an adopter
    // can run the flag across a representative N PRs and feed the
    // resulting CSV back as tuning data (issue #5). The output is
    // deliberately plain — no JSON, no schema versioning — because the
    // intended consumer is a one-off awk/jq pipeline, not a long-lived
    // integration. Format: `kind|key|score|threshold`. No telemetry: the
    // user owns the bytes and pipes them wherever they want.
    if args.debug_calibration {
        write_calibration_lines(&enrichment, &mut std::io::stderr());
    }

    // CLI flag wins; otherwise the env var supplies the default. Empty
    // strings are treated as unset to match shell-script callers that
    // pass `BOMDRIFT_REPO_URL=` to clear the value rather than `unset`.
    // GitLab CI exposes the project URL as `CI_PROJECT_URL` (analog of
    // GitHub's `GITHUB_REPOSITORY`-derived URL); honor it as a third
    // fallback so users on the GitLab template don't have to plumb
    // `BOMDRIFT_REPO_URL` themselves.
    let repo_url = args
        .repo_url
        .clone()
        .or_else(|| std::env::var("BOMDRIFT_REPO_URL").ok())
        .or_else(|| std::env::var("CI_PROJECT_URL").ok())
        .filter(|s| !s.is_empty());

    // Platform precedence: explicit `--platform` (or `[diff] platform`
    // in `.bomdrift.toml`, already merged into `args.platform`) wins;
    // otherwise auto-detect from CI env. `GITLAB_CI=true` is GitLab's
    // canonical CI marker — set unconditionally on every job in every
    // GitLab pipeline. Fall through to `Platform::GitHub` (the default)
    // so existing GitHub Action consumers see no behavior change.
    let platform = args.platform.unwrap_or_else(|| {
        if std::env::var("GITLAB_CI").is_ok_and(|v| v == "true") {
            crate::cli::Platform::GitLab
        } else {
            crate::cli::Platform::GitHub
        }
    });
    let md_options = render::markdown::Options {
        summary_only: args.summary_only,
        findings_only: args.findings_only,
        repo_url,
        platform: platform.into(),
    };
    let rendered = match output {
        OutputFormat::Terminal => {
            // ANSI escapes are only safe on a real TTY. Piped/redirected stdout
            // (e.g. captured by a CI step that posts a PR comment) must stay
            // plain markdown so it renders correctly in a comment body.
            if std::io::stdout().is_terminal() {
                render::term::render(&cs, &enrichment)
            } else {
                render::markdown::render_with_options(&cs, &enrichment, md_options)
            }
        }
        OutputFormat::Markdown => {
            render::markdown::render_with_options(&cs, &enrichment, md_options)
        }
        OutputFormat::Json => render::json::render(&cs, &enrichment),
        OutputFormat::Sarif => render::sarif::render(&cs, &enrichment),
    };

    print!("{rendered}");

    // Body must be fully written before we exit-2 — the action's `tee`
    // wrapper still wants the comment posted even when fail-on trips.
    let budget_tripped = budget_tripped(
        &cs,
        args.max_added,
        args.max_removed,
        args.max_version_changed,
    );
    if budget_tripped {
        log_budget_trips(
            &cs,
            args.max_added,
            args.max_removed,
            args.max_version_changed,
        );
    }

    if tripped(&cs, &enrichment, fail_on) || budget_tripped {
        std::process::exit(FAIL_ON_EXIT_CODE);
    }

    Ok(())
}

/// Pure helper: does this `(changeset, enrichment)` pair trip the configured
/// fail-on threshold? Side-effect-free so the policy is easy to unit-test
/// without spinning up the full pipeline.
///
/// `FailOn::CriticalCve` filters on real severity now that OSV `/v1/vulns/{id}`
/// is fetched; only advisories with [`Severity::High`] or higher trip it.
/// (High is included because GHSA's `CRITICAL` label is relatively rare —
/// many actively-exploited supply-chain advisories ship as `HIGH`. Treating
/// "critical-cve" as "high-or-critical" matches what the option's name
/// communicates to a CI policy author: "block on the actionable bucket".)
pub fn tripped(cs: &ChangeSet, e: &Enrichment, threshold: FailOn) -> bool {
    match threshold {
        FailOn::None => false,
        FailOn::Cve => !e.vulns.is_empty(),
        FailOn::CriticalCve => any_advisory_at_or_above(e, Severity::High),
        FailOn::Typosquat => !e.typosquats.is_empty(),
        FailOn::LicenseChange => !cs.license_changed.is_empty(),
        FailOn::Any => e.has_findings() || !cs.license_changed.is_empty(),
    }
}

pub fn budget_tripped(
    cs: &ChangeSet,
    max_added: Option<usize>,
    max_removed: Option<usize>,
    max_version_changed: Option<usize>,
) -> bool {
    max_added.is_some_and(|max| cs.added.len() > max)
        || max_removed.is_some_and(|max| cs.removed.len() > max)
        || max_version_changed.is_some_and(|max| cs.version_changed.len() > max)
}

/// Emit one CSV-friendly line per finding to the given writer, capturing
/// the score and the constant it was compared against. Off by default
/// (driven by `--debug-calibration`); when set, the user pipes stderr
/// to a file and feeds the resulting CSV back as tuning data.
///
/// Schema: `kind|key|score|threshold` — pipe-delimited because purls
/// already contain commas (`pkg:npm/@scope/name`) which would force CSV
/// quoting. `kind` ∈ {`typosquat`, `version-jump`, `maintainer-age`,
/// `cve`}. `score` is the underlying numeric the enricher computed
/// (similarity for typosquat, major-version delta for version-jump,
/// days-old for maintainer-age, max CVSS-equivalent for cve);
/// `threshold` is the constant the score was gated against. CVE rows
/// surface every advisory (no internal threshold) so adopters can see
/// the score distribution before tuning `--fail-on critical-cve`.
fn write_calibration_lines<W: std::io::Write>(e: &Enrichment, out: &mut W) {
    use crate::enrich::maintainer::YOUNG_MAINTAINER_DAYS;
    use crate::enrich::typosquat::SIMILARITY_THRESHOLD;
    use crate::enrich::version_jump::MIN_MAJOR_DELTA;

    for f in &e.typosquats {
        let _ = writeln!(
            out,
            "typosquat|{}|{:.4}|{:.4}",
            f.component
                .purl
                .as_deref()
                .unwrap_or(f.component.name.as_str()),
            f.score,
            SIMILARITY_THRESHOLD,
        );
    }
    for f in &e.version_jumps {
        let _ = writeln!(
            out,
            "version-jump|{}|{}|{}",
            f.after
                .purl
                .as_deref()
                .unwrap_or(f.after.name.as_str()),
            f.after_major.saturating_sub(f.before_major),
            MIN_MAJOR_DELTA,
        );
    }
    for f in &e.maintainer_age {
        let _ = writeln!(
            out,
            "maintainer-age|{}|{}|{}",
            f.component
                .purl
                .as_deref()
                .unwrap_or(f.component.name.as_str()),
            f.days_old,
            YOUNG_MAINTAINER_DAYS,
        );
    }
    for (purl, refs) in &e.vulns {
        for vuln in refs {
            // Severity has no numeric score in our model; emit the
            // bucket label as a non-numeric "score" so the CSV row is
            // still well-formed. Adopters who want raw CVSS can grep
            // the JSON output instead — the calibration tap is for the
            // ranked-bucket choice (cve vs critical-cve), not for
            // reverse-engineering CVSS.
            let _ = writeln!(
                out,
                "cve|{}#{}|{}|high+",
                purl,
                vuln.id,
                vuln.severity.as_str(),
            );
        }
    }
}

fn log_budget_trips(
    cs: &ChangeSet,
    max_added: Option<usize>,
    max_removed: Option<usize>,
    max_version_changed: Option<usize>,
) {
    if let Some(max) = max_added.filter(|max| cs.added.len() > *max) {
        eprintln!(
            "bomdrift: policy gate tripped: added count {} exceeds --max-added {}",
            cs.added.len(),
            max
        );
    }
    if let Some(max) = max_removed.filter(|max| cs.removed.len() > *max) {
        eprintln!(
            "bomdrift: policy gate tripped: removed count {} exceeds --max-removed {}",
            cs.removed.len(),
            max
        );
    }
    if let Some(max) = max_version_changed.filter(|max| cs.version_changed.len() > *max) {
        eprintln!(
            "bomdrift: policy gate tripped: version-changed count {} exceeds --max-version-changed {}",
            cs.version_changed.len(),
            max
        );
    }
}

fn any_advisory_at_or_above(e: &Enrichment, threshold: Severity) -> bool {
    e.vulns.values().flatten().any(|v| v.severity >= threshold)
}

const INIT_CONFIG: &str = r#"# bomdrift repo policy.
# CLI flags override these defaults for one-off runs.

[diff]
fail_on = "critical-cve"
baseline = ".bomdrift/baseline.json"
findings_only = false

# Optional churn budgets. Uncomment to fail the workflow when a PR changes too
# many dependencies at once.
# max_added = 25
# max_removed = 50
# max_version_changed = 10
"#;

const INIT_SBOM_WORKFLOW: &str = r#"name: SBOM diff

on: pull_request

permissions:
  contents: read
  pull-requests: write

jobs:
  diff:
    runs-on: ubuntu-latest
    steps:
      - uses: Metbcy/bomdrift@v1
        with:
          config: .bomdrift.toml
"#;

const INIT_SUPPRESS_WORKFLOW: &str = r#"name: bomdrift suppress

on:
  issue_comment:
    types: [created]

permissions:
  contents: write
  pull-requests: write

jobs:
  suppress:
    if: |
      github.event.issue.pull_request &&
      startsWith(github.event.comment.body, '/bomdrift suppress ')
    runs-on: ubuntu-latest
    steps:
      - uses: Metbcy/bomdrift/comment-suppress@v1
"#;

fn load_sbom(
    path: &Path,
    format_hint: Option<model::SbomFormat>,
    include_file_components: bool,
) -> Result<model::Sbom> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("reading SBOM file: {}", path.display()))?;
    let value: serde_json::Value = serde_json::from_str(&raw)
        .with_context(|| format!("parsing JSON in: {}", path.display()))?;
    let mut sbom = parse::parse_with_format(value, format_hint)
        .with_context(|| format!("normalizing SBOM from: {}", path.display()))?;
    if !include_file_components {
        parse::filter_file_components(&mut sbom);
    }
    Ok(sbom)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    use crate::enrich::typosquat::TyposquatFinding;
    use crate::enrich::version_jump::VersionJumpFinding;
    use crate::enrich::{Severity, VulnRef};
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

    fn enrichment_with_cve_at(severity: Severity) -> Enrichment {
        let mut vulns: HashMap<String, Vec<VulnRef>> = HashMap::new();
        vulns.insert(
            "pkg:npm/foo@1.0.0".into(),
            vec![VulnRef {
                id: "CVE-2025-1".into(),
                severity,
            }],
        );
        Enrichment {
            vulns,
            ..Default::default()
        }
    }

    fn enrichment_with_cve() -> Enrichment {
        // Severity::None is what every v0.2-era test implicitly assumed — the
        // pre-severity world. Tests that don't care about the bucket use this.
        enrichment_with_cve_at(Severity::None)
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
    fn fail_on_critical_cve_filters_on_severity_high_or_above() {
        // Critical and High advisories trip; Medium / Low / None don't. The
        // doc on `tripped()` explains why High is included in the
        // "critical-cve" bucket.
        assert!(tripped(
            &ChangeSet::default(),
            &enrichment_with_cve_at(Severity::Critical),
            FailOn::CriticalCve
        ));
        assert!(tripped(
            &ChangeSet::default(),
            &enrichment_with_cve_at(Severity::High),
            FailOn::CriticalCve
        ));
        assert!(!tripped(
            &ChangeSet::default(),
            &enrichment_with_cve_at(Severity::Medium),
            FailOn::CriticalCve
        ));
        assert!(!tripped(
            &ChangeSet::default(),
            &enrichment_with_cve_at(Severity::None),
            FailOn::CriticalCve
        ));
    }

    #[test]
    fn fail_on_cve_still_trips_on_severity_none_advisories() {
        // --fail-on cve is the broad "any advisory" bucket; severity threading
        // doesn't change its semantics. An advisory with unresolved severity
        // still trips it (the alternative — silent suppression — would be the
        // real footgun).
        assert!(tripped(
            &ChangeSet::default(),
            &enrichment_with_cve_at(Severity::None),
            FailOn::Cve
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
    fn fail_on_license_change_trips_only_on_license_changes() {
        assert!(tripped(
            &cs_with_license_change(),
            &Enrichment::default(),
            FailOn::LicenseChange
        ));
        assert!(!tripped(
            &ChangeSet::default(),
            &enrichment_with_cve(),
            FailOn::LicenseChange
        ));
        assert!(!tripped(
            &ChangeSet::default(),
            &enrichment_with_typosquat(),
            FailOn::LicenseChange
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

    #[test]
    fn budget_trips_when_counts_exceed_limits() {
        let cs = ChangeSet {
            added: vec![comp("a"), comp("b")],
            removed: vec![comp("c")],
            version_changed: vec![(comp("d"), comp("d"))],
            ..Default::default()
        };
        assert!(budget_tripped(&cs, Some(1), None, None));
        assert!(budget_tripped(&cs, None, Some(0), None));
        assert!(budget_tripped(&cs, None, None, Some(0)));
        assert!(!budget_tripped(&cs, Some(2), Some(1), Some(1)));
    }
}
