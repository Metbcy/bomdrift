use crate::cli::FailOn;
use crate::diff::ChangeSet;
use crate::enrich::{Enrichment, Severity};

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
        FailOn::Kev => any_kev(e),
        FailOn::LicenseViolation => !e.license_violations.is_empty(),
        FailOn::RecentlyPublished => !e.recently_published.is_empty(),
        FailOn::Deprecated => !e.deprecated.is_empty(),
        FailOn::Any => e.has_findings() || !cs.license_changed.is_empty() || any_kev(e),
    }
}

/// True when any advisory across all components has its CISA KEV flag set.
pub fn any_kev(e: &Enrichment) -> bool {
    e.vulns.values().any(|refs| refs.iter().any(|r| r.kev))
}

/// True when any advisory has an EPSS score >= the threshold.
pub fn any_epss_at_or_above(e: &Enrichment, threshold: f32) -> bool {
    e.vulns.values().any(|refs| {
        refs.iter()
            .any(|r| r.epss_score.is_some_and(|s| s >= threshold))
    })
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

pub(super) fn any_advisory_at_or_above(e: &Enrichment, threshold: Severity) -> bool {
    e.vulns.values().flatten().any(|v| v.severity >= threshold)
}
