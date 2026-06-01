use std::fs;
use std::io::IsTerminal;
use std::path::Path;

use anyhow::{Context, Result};

use crate::cli::{self, DiffArgs, FailOn, OutputFormat};
use crate::diff::ChangeSet;
use crate::{attestation, baseline, config, diff, enrich, model, parse, plugin, render, vex};

use super::FAIL_ON_EXIT_CODE;
use super::calibration::{CalibrationOverrides, write_calibration_lines};
use super::predicates::{any_epss_at_or_above, budget_tripped, tripped};

pub(super) fn run_diff(mut args: DiffArgs) -> Result<()> {
    config::apply_diff_config(&mut args)?;

    if args.require_attestation
        && (args.before_attestation.is_none() || args.after_attestation.is_none())
    {
        anyhow::bail!(
            "--require-attestation needs both --before-attestation and --after-attestation"
        );
    }

    let output = args.output.unwrap_or(OutputFormat::Terminal);
    let format = args.format.unwrap_or(cli::InputFormat::Auto);
    let fail_on = args.fail_on.unwrap_or(FailOn::None);

    let format_hint = format.to_sbom_format();
    let before = load_sbom_or_attestation(
        args.before.as_deref(),
        args.before_attestation.as_deref(),
        args.cosign_identity.as_deref(),
        args.cosign_issuer.as_deref(),
        format_hint,
        args.include_file_components,
        "before",
        args.debug_calibration,
        args.debug_calibration_format,
    )?;
    let after = load_sbom_or_attestation(
        args.after.as_deref(),
        args.after_attestation.as_deref(),
        args.cosign_identity.as_deref(),
        args.cosign_issuer.as_deref(),
        format_hint,
        args.include_file_components,
        "after",
        args.debug_calibration,
        args.debug_calibration_format,
    )?;

    let mut cs = diff::diff(&before, &after);

    let mut enrichment = if args.no_osv {
        enrich::Enrichment::default()
    } else {
        // OSV enrichment is best-effort. Network failures must not block the diff
        // from rendering — a PR review is still useful without CVE data.
        match enrich::osv::enrich_cached_with_ttl(&cs, args.no_osv_cache, args.cache_ttl_hours) {
            Ok(e) => e,
            Err(err) => {
                eprintln!("warning: OSV enrichment failed, continuing without it: {err:#}");
                enrich::Enrichment::default()
            }
        }
    };

    // EPSS / KEV enrichment piggyback on OSV's VulnRefs and only have
    // anything to do when there are CVE-aliased advisories. Skip both if
    // there are no vulns.
    if !args.no_epss
        && !enrichment.vulns.is_empty()
        && let Err(err) = enrich::epss::enrich_with_ttl(&mut enrichment, args.cache_ttl_hours)
    {
        eprintln!("warning: EPSS enrichment failed, continuing without it: {err:#}");
    }
    if !args.no_kev
        && !enrichment.vulns.is_empty()
        && let Err(err) = enrich::kev::enrich_with_ttl(&mut enrichment, args.cache_ttl_hours)
    {
        eprintln!("warning: KEV enrichment failed, continuing without it: {err:#}");
    }

    // Typosquat detection is pure-compute (embedded reference list) and always
    // runs, regardless of `--no-osv`. Findings are informational.
    enrichment.typosquats =
        enrich::typosquat::enrich_with_threshold(&cs, args.typosquat_similarity_threshold);

    // Multi-major version-jump detection is pure-compute and also always runs.
    // Findings are informational.
    enrichment.version_jumps = enrich::version_jump::enrich_with(&cs, args.multi_major_delta);

    // Maintainer-age enrichment hits the GitHub REST API; gated behind
    // `--no-maintainer-age` for offline runs. Best-effort: failures warn and
    // continue, mirroring the OSV enricher's contract.
    if !args.no_maintainer_age {
        match enrich::maintainer::enrich_with_hosts(
            &cs,
            "https://api.github.com",
            std::time::Duration::from_secs(15),
            args.young_maintainer_days,
        ) {
            Ok(findings) => enrichment.maintainer_age = findings,
            Err(err) => {
                eprintln!(
                    "warning: maintainer-age enrichment failed, continuing without it: {err:#}"
                );
            }
        }
    }

    // License-policy enrichment (Phase D, v0.8). Pure-compute, runs after
    // OSV/EPSS/KEV. Empty allow + empty deny means "no policy" — the
    // enricher returns no violations.
    let license_policy = enrich::license::Policy {
        allow: args.allow_licenses.clone(),
        deny: args.deny_licenses.clone(),
        allow_ambiguous: args.allow_ambiguous_licenses,
        allow_exceptions: args.allow_exception.clone(),
        deny_exceptions: args.deny_exception.clone(),
    };
    enrichment.license_violations = enrich::license::enrich(&cs, &license_policy);

    // Registry-metadata enrichers (Phase K, v0.9). Best-effort — a
    // registry timeout returns Ok with no findings.
    if !args.no_registry {
        let findings =
            enrich::registry::enrich(&cs, args.recently_published_days, args.cache_ttl_hours);
        enrichment.recently_published = findings.recently_published;
        enrichment.deprecated = findings.deprecated;
        enrichment.maintainer_set_changed = findings.maintainer_set_changed;
    }

    // Plugin findings (Phase C, v0.9.6). Run after every built-in
    // enricher so plugins observe the same `cs` view bomdrift renders;
    // before baseline so plugin findings can be baselined too. Plugin
    // failures degrade gracefully — a malformed manifest aborts the
    // run (config error), but plugin runtime failures emit only a
    // BOMDRIFT_DEBUG-gated stderr warning and contribute no findings.
    if !args.plugin.is_empty() {
        let mut manifests = Vec::with_capacity(args.plugin.len());
        for path in &args.plugin {
            let manifest = plugin::load_manifest(path)
                .with_context(|| format!("loading --plugin {}", path.display()))?;
            manifests.push(manifest);
        }
        enrichment.plugin_findings = plugin::run_plugins(&manifests, &cs);
    }

    // Apply the baseline AFTER all enrichers run — suppression operates on
    // the realized finding set, not on intermediate inputs. This keeps the
    // baseline file format stable as new enrichers are added: a new finding
    // type that the baseline doesn't know about simply isn't suppressed.
    let mut baseline_entries: Vec<crate::baseline::BaselineEntry> = Vec::new();
    if let Some(path) = &args.baseline {
        let baseline = baseline::Baseline::load(path)?;
        for ent in &baseline.expired_entries {
            eprintln!(
                "warning: baseline entry {id}{purl} expired {expires}; finding will surface in this run{reason}",
                id = ent.id,
                purl = ent
                    .purl
                    .as_deref()
                    .map(|p| format!(" ({p})"))
                    .unwrap_or_default(),
                expires = ent.expires.as_deref().unwrap_or(""),
                reason = ent
                    .reason
                    .as_deref()
                    .map(|r| format!(" — was: {r}"))
                    .unwrap_or_default(),
            );
        }
        baseline_entries = baseline.entries.clone();
        baseline::apply(&mut cs, &mut enrichment, &baseline);
    }

    // VEX consumption (Phase G, v0.9). Applied AFTER baseline so VEX
    // statements operate on the post-baseline view — this matches what
    // a downstream tool would see and avoids double-counting "already
    // suppressed" findings in the VEX-suppressed tally.
    if !args.vex.is_empty() {
        match vex::load(&args.vex) {
            Ok(stmts) => {
                let idx = vex::VexIndex::build(stmts);
                vex::apply(&mut enrichment, &idx);
            }
            Err(err) => {
                eprintln!("warning: VEX load failed, continuing without VEX filtering: {err:#}");
            }
        }
    }

    // VEX emission (Phase H, v0.9). Writes a single OpenVEX 0.2.0 doc
    // to the requested path, covering baseline-suppressed entries and
    // un-suppressed findings. Byte-deterministic when SOURCE_DATE_EPOCH
    // is set.
    if let Some(path) = &args.emit_vex {
        let author = args
            .vex_author
            .clone()
            .or_else(|| args.repo_url.clone())
            .or_else(|| std::env::var("BOMDRIFT_REPO_URL").ok())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "bomdrift".to_string());
        let default_just = args
            .vex_default_justification
            .clone()
            .unwrap_or_else(|| "vulnerable_code_not_in_execute_path".to_string());
        let opts = vex::EmitOptions {
            author: &author,
            default_justification: &default_just,
            baseline_entries: &baseline_entries,
        };
        let body = vex::emit(&cs, &enrichment, &opts);
        std::fs::write(path, body)
            .with_context(|| format!("writing --emit-vex {}", path.display()))?;
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
        write_calibration_lines(
            &enrichment,
            &mut std::io::stderr(),
            args.debug_calibration_format,
            CalibrationOverrides {
                similarity_threshold: args.typosquat_similarity_threshold,
                young_maintainer_days: args.young_maintainer_days,
                multi_major_delta: args.multi_major_delta,
            },
        );
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
        .or_else(|| std::env::var("BITBUCKET_GIT_HTTP_ORIGIN").ok())
        .or_else(|| std::env::var("BUILD_REPOSITORY_URI").ok())
        .filter(|s| !s.is_empty());

    // Platform precedence: explicit `--platform` (or `[diff] platform`
    // in `.bomdrift.toml`, already merged into `args.platform`) wins;
    // otherwise auto-detect from CI env. Detection order: GitLab
    // (`GITLAB_CI=true`), Bitbucket (`BITBUCKET_BUILD_NUMBER`), Azure
    // DevOps (`TF_BUILD`), then default GitHub.
    let platform = args.platform.unwrap_or_else(|| {
        if std::env::var("GITLAB_CI").is_ok_and(|v| v == "true") {
            crate::cli::Platform::GitLab
        } else if std::env::var("BITBUCKET_BUILD_NUMBER").is_ok() {
            crate::cli::Platform::Bitbucket
        } else if std::env::var("TF_BUILD").is_ok() {
            crate::cli::Platform::AzureDevOps
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
        OutputFormat::Html => render::html::render(&cs, &enrichment),
    };

    if let Some(path) = &args.output_file {
        std::fs::write(path, &rendered)
            .with_context(|| format!("writing --output-file {}", path.display()))?;
    } else {
        print!("{rendered}");
    }

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

    let epss_tripped = args
        .fail_on_epss
        .is_some_and(|threshold| any_epss_at_or_above(&enrichment, threshold));
    if epss_tripped {
        let threshold = args.fail_on_epss.unwrap_or(0.0);
        eprintln!(
            "bomdrift: policy gate tripped: --fail-on-epss {threshold:.2} (one or more advisories at or above this score)"
        );
    }

    if tripped(&cs, &enrichment, fail_on) || budget_tripped || epss_tripped {
        std::process::exit(FAIL_ON_EXIT_CODE);
    }

    Ok(())
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

fn load_sbom(
    path: &Path,
    format_hint: Option<model::SbomFormat>,
    include_file_components: bool,
) -> Result<model::Sbom> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("reading SBOM file: {}", path.display()))?;
    parse_sbom_bytes(
        &raw,
        &path.display().to_string(),
        format_hint,
        include_file_components,
    )
}

fn parse_sbom_bytes(
    raw: &str,
    source_label: &str,
    format_hint: Option<model::SbomFormat>,
    include_file_components: bool,
) -> Result<model::Sbom> {
    let value: serde_json::Value =
        serde_json::from_str(raw).with_context(|| format!("parsing JSON in: {source_label}"))?;
    let mut sbom = parse::parse_with_format(value, format_hint)
        .with_context(|| format!("normalizing SBOM from: {source_label}"))?;
    if !include_file_components {
        parse::filter_file_components(&mut sbom);
    }
    Ok(sbom)
}

#[allow(clippy::too_many_arguments)]
fn load_sbom_or_attestation(
    path: Option<&Path>,
    oci_ref: Option<&str>,
    cosign_identity: Option<&str>,
    cosign_issuer: Option<&str>,
    format_hint: Option<model::SbomFormat>,
    include_file_components: bool,
    side: &str,
    debug_calibration: bool,
    debug_format: crate::cli::DebugFormat,
) -> Result<model::Sbom> {
    if let Some(oci) = oci_ref {
        let identity = cosign_identity.ok_or_else(|| {
            anyhow::anyhow!(
                "--{side}-attestation requires --cosign-identity (regex passed to cosign --certificate-identity-regexp)"
            )
        })?;
        let issuer = cosign_issuer.ok_or_else(|| {
            anyhow::anyhow!(
                "--{side}-attestation requires --cosign-issuer (URL passed to cosign --certificate-oidc-issuer)"
            )
        })?;
        let body = attestation::fetch_verified_sbom(oci, identity, issuer)
            .with_context(|| format!("fetching --{side}-attestation {oci}"))?;
        if debug_calibration {
            // One row per verified attestation; surfaces the cert
            // regex cosign accepted so adopters can confirm policy.
            let _ =
                write_attestation_calibration(&mut std::io::stderr(), oci, identity, debug_format);
        }
        return parse_sbom_bytes(
            &body,
            &format!("attestation:{oci}"),
            format_hint,
            include_file_components,
        );
    }
    let path = path.ok_or_else(|| {
        anyhow::anyhow!(
            "internal: {side} requires either a positional path or --{side}-attestation"
        )
    })?;
    load_sbom(path, format_hint, include_file_components)
}

fn write_attestation_calibration<W: std::io::Write>(
    out: &mut W,
    oci_ref: &str,
    identity: &str,
    format: crate::cli::DebugFormat,
) -> std::io::Result<()> {
    match format {
        crate::cli::DebugFormat::Pipe => {
            writeln!(out, "attestation|{oci_ref}|verified|{identity}")
        }
        crate::cli::DebugFormat::Jsonl => {
            let row = serde_json::json!({
                "kind": "attestation",
                "key": oci_ref,
                "score": "verified",
                "threshold": identity,
            });
            writeln!(out, "{row}")
        }
    }
}
