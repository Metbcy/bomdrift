use crate::{diff::ChangeSet, enrich::Enrichment};
use std::fmt::Write;

pub(crate) fn render(cs: &ChangeSet, enrichment: &Enrichment) -> String {
    let mut out = String::new();

    out.push_str("| Change | Count |\n|---|---:|\n");
    let _ = writeln!(out, "| Added | {} |", cs.added.len());
    let _ = writeln!(out, "| Removed | {} |", cs.removed.len());
    let _ = writeln!(out, "| Version changed | {} |", cs.version_changed.len());
    let _ = writeln!(out, "| License changed | {} |", cs.license_changed.len());
    if !enrichment.vulns.is_empty() {
        let _ = writeln!(
            out,
            "| Vulnerabilities | {} |",
            enrichment.vulns.values().map(Vec::len).sum::<usize>()
        );
    }
    if !enrichment.typosquats.is_empty() {
        let _ = writeln!(
            out,
            "| Possible typosquats | {} |",
            enrichment.typosquats.len()
        );
    }
    if !enrichment.version_jumps.is_empty() {
        let _ = writeln!(
            out,
            "| Multi-major version jumps | {} |",
            enrichment.version_jumps.len()
        );
    }
    if !enrichment.maintainer_age.is_empty() {
        let _ = writeln!(
            out,
            "| Young maintainers | {} |",
            enrichment.maintainer_age.len()
        );
    }
    if !enrichment.license_violations.is_empty() {
        let _ = writeln!(
            out,
            "| License violations | {} |",
            enrichment.license_violations.len()
        );
    }
    if !enrichment.recently_published.is_empty() {
        let _ = writeln!(
            out,
            "| Recently published | {} |",
            enrichment.recently_published.len()
        );
    }
    if !enrichment.deprecated.is_empty() {
        let _ = writeln!(out, "| Deprecated | {} |", enrichment.deprecated.len());
    }
    if !enrichment.maintainer_set_changed.is_empty() {
        let _ = writeln!(
            out,
            "| Maintainer set changed | {} |",
            enrichment.maintainer_set_changed.len()
        );
    }
    if !enrichment.plugin_findings.is_empty() {
        let _ = writeln!(
            out,
            "| Plugin findings | {} |",
            enrichment.plugin_findings.len()
        );
    }
    if enrichment.vex_suppressed_count > 0 {
        let _ = writeln!(
            out,
            "| Suppressed by VEX | {} |",
            enrichment.vex_suppressed_count
        );
    }
    out.push('\n');

    out
}
