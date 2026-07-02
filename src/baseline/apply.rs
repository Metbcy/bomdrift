//! The suppression pass: drop every live finding whose match key is present
//! in the loaded baseline. Mutates the enrichment in place.

use crate::diff::ChangeSet;
use crate::enrich::Enrichment;

use super::Baseline;

/// Apply `baseline` to `enrichment` (and vulns within `cs.added` / `cs.version_changed`
/// implicitly via the `vulns` map). Mutates in place — every match-key the
/// baseline contains is dropped from the live enrichment, so downstream
/// renderers and `tripped()` see a post-suppression view.
pub fn apply(_cs: &mut ChangeSet, e: &mut Enrichment, baseline: &Baseline) {
    if baseline.is_empty() {
        return;
    }

    // Vulns: drop matched advisories per-purl. When a purl loses its last
    // advisory, drop the purl entry entirely so the markdown summary's
    // "Vulnerabilities | N |" row doesn't lie about empty entries.
    // The `suppressed_advisories` set is a wildcard match — any advisory
    // ID in it is dropped regardless of purl.
    e.vulns.retain(|purl, refs| {
        refs.retain(|r| {
            !baseline.vuln_keys.contains(&(purl.clone(), r.id.clone()))
                && !baseline.suppressed_advisories.contains(&r.id)
        });
        !refs.is_empty()
    });

    e.typosquats.retain(|f| {
        let purl = f.component.purl.clone().unwrap_or_default();
        !baseline.typosquat_keys.contains(&(purl, f.closest.clone()))
    });

    e.version_jumps.retain(|f| {
        let purl = f.after.purl.clone().unwrap_or_default();
        !baseline
            .version_jump_keys
            .contains(&(purl, f.before_major, f.after_major))
    });

    e.maintainer_age.retain(|f| {
        let purl = f.component.purl.clone().unwrap_or_default();
        !baseline
            .young_maintainer_keys
            .contains(&(purl, f.top_contributor.clone()))
    });
}
