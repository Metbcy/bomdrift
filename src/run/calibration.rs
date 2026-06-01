use crate::enrich::Enrichment;

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
/// Active overrides for the configurable calibration thresholds. Threaded
/// into [`write_calibration_lines`] so emitted rows reflect the effective
/// threshold the enricher actually used, not the unconditional const default.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct CalibrationOverrides {
    pub similarity_threshold: Option<f64>,
    pub young_maintainer_days: Option<i64>,
    pub multi_major_delta: Option<u32>,
}

pub(super) fn write_calibration_lines<W: std::io::Write>(
    e: &Enrichment,
    out: &mut W,
    format: crate::cli::DebugFormat,
    overrides: CalibrationOverrides,
) {
    use crate::enrich::maintainer::YOUNG_MAINTAINER_DAYS;
    use crate::enrich::typosquat::SIMILARITY_THRESHOLD;
    use crate::enrich::version_jump::MIN_MAJOR_DELTA;

    let active_similarity = overrides
        .similarity_threshold
        .unwrap_or(SIMILARITY_THRESHOLD);
    let active_young = overrides
        .young_maintainer_days
        .unwrap_or(YOUNG_MAINTAINER_DAYS);
    let active_major_delta = overrides.multi_major_delta.unwrap_or(MIN_MAJOR_DELTA);

    for f in &e.typosquats {
        write_calibration_row(
            out,
            "typosquat",
            f.component
                .purl
                .as_deref()
                .unwrap_or(f.component.name.as_str()),
            CalibrationScore::Float(f.score),
            CalibrationThreshold::Float(active_similarity),
            format,
        );
    }
    for f in &e.version_jumps {
        write_calibration_row(
            out,
            "version-jump",
            f.after.purl.as_deref().unwrap_or(f.after.name.as_str()),
            CalibrationScore::Int(f.after_major.saturating_sub(f.before_major) as i64),
            CalibrationThreshold::Int(active_major_delta as i64),
            format,
        );
    }
    for f in &e.maintainer_age {
        write_calibration_row(
            out,
            "maintainer-age",
            f.component
                .purl
                .as_deref()
                .unwrap_or(f.component.name.as_str()),
            CalibrationScore::Int(f.days_old),
            CalibrationThreshold::Int(active_young),
            format,
        );
    }
    for (purl, refs) in &e.vulns {
        for vuln in refs {
            // Severity has no numeric score in our model; emit the bucket
            // label as a non-numeric "score" so the row stays well-formed
            // (string in JSONL, plain token in pipe).
            write_calibration_row(
                out,
                "cve",
                &format!("{purl}#{}", vuln.id),
                CalibrationScore::Text(vuln.severity.as_str()),
                CalibrationThreshold::Text("high+"),
                format,
            );
            for cve in vuln.cves() {
                if let Some(score) = vuln.epss_score {
                    write_calibration_row(
                        out,
                        "epss",
                        &format!("{purl}+{cve}"),
                        CalibrationScore::Float(score as f64),
                        CalibrationThreshold::Float(0.5),
                        format,
                    );
                }
                if vuln.kev {
                    write_calibration_row(
                        out,
                        "kev",
                        &format!("{purl}+{cve}"),
                        CalibrationScore::Text("true"),
                        CalibrationThreshold::Text("kev"),
                        format,
                    );
                }
            }
        }
    }
    for v in &e.license_violations {
        // Threshold field carries the precise matched_rule (e.g.
        // "deny: GPL-3.0-only" or "exception:LLVM-exception denied")
        // so calibration consumers see the WHY, not just the kind tag.
        write_calibration_row(
            out,
            "license",
            v.component
                .purl
                .as_deref()
                .unwrap_or(v.component.name.as_str()),
            CalibrationScore::Text(&v.license),
            CalibrationThreshold::Text(&v.matched_rule),
            format,
        );
    }
    for f in &e.recently_published {
        write_calibration_row(
            out,
            "recently-published",
            f.component
                .purl
                .as_deref()
                .unwrap_or(f.component.name.as_str()),
            CalibrationScore::Int(f.days_old),
            CalibrationThreshold::Int(crate::enrich::registry::MIN_PUBLISHED_AGE_DAYS),
            format,
        );
    }
    for f in &e.deprecated {
        write_calibration_row(
            out,
            "deprecated",
            f.component
                .purl
                .as_deref()
                .unwrap_or(f.component.name.as_str()),
            CalibrationScore::Text(f.message.as_deref().unwrap_or("(deprecated)")),
            CalibrationThreshold::Text("any"),
            format,
        );
    }
    for f in &e.maintainer_set_changed {
        write_calibration_row(
            out,
            "maintainer-set-changed",
            f.after.purl.as_deref().unwrap_or(f.after.name.as_str()),
            CalibrationScore::Int((f.added.len() + f.removed.len()) as i64),
            CalibrationThreshold::Int(1),
            format,
        );
    }
}

/// Numeric or symbolic score for a calibration row. Float/Int rendered
/// without quotes in JSONL; Text rendered as a JSON string.
pub(crate) enum CalibrationScore<'a> {
    Float(f64),
    Int(i64),
    Text(&'a str),
}

pub(crate) enum CalibrationThreshold<'a> {
    Float(f64),
    Int(i64),
    Text(&'a str),
}

/// Single dispatch point for both pipe and JSONL calibration formats.
/// Adding a new finding kind is one call site, not two — the format
/// branches stay localized to this helper.
pub(crate) fn write_calibration_row<W: std::io::Write>(
    out: &mut W,
    kind: &str,
    key: &str,
    score: CalibrationScore<'_>,
    threshold: CalibrationThreshold<'_>,
    format: crate::cli::DebugFormat,
) {
    match format {
        crate::cli::DebugFormat::Pipe => {
            let score_s = match score {
                CalibrationScore::Float(v) => format!("{v:.4}"),
                CalibrationScore::Int(v) => v.to_string(),
                CalibrationScore::Text(s) => s.to_string(),
            };
            let thr_s = match threshold {
                CalibrationThreshold::Float(v) => format!("{v:.4}"),
                CalibrationThreshold::Int(v) => v.to_string(),
                CalibrationThreshold::Text(s) => s.to_string(),
            };
            let _ = writeln!(out, "{kind}|{key}|{score_s}|{thr_s}");
        }
        crate::cli::DebugFormat::Jsonl => {
            let score_v = match score {
                CalibrationScore::Float(v) => serde_json::Value::from(v),
                CalibrationScore::Int(v) => serde_json::Value::from(v),
                CalibrationScore::Text(s) => serde_json::Value::from(s),
            };
            let thr_v = match threshold {
                CalibrationThreshold::Float(v) => serde_json::Value::from(v),
                CalibrationThreshold::Int(v) => serde_json::Value::from(v),
                CalibrationThreshold::Text(s) => serde_json::Value::from(s),
            };
            let line = serde_json::json!({
                "kind": kind,
                "key": key,
                "score": score_v,
                "threshold": thr_v,
            });
            let _ = writeln!(out, "{line}");
        }
    }
}
