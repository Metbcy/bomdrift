//! Risk-signal enrichers. Each runs over a [`crate::diff::ChangeSet`] and produces
//! data that the renderers can pair back to the changed components.
//!
//! v0 ships [`osv`] (CVE lookup via OSV.dev) and [`typosquat`] (similarity to
//! popular npm packages). Maintainer-age and version-jump enrichers land in
//! subsequent PRs.

pub mod osv;
pub mod typosquat;

use std::collections::HashMap;

use typosquat::TyposquatFinding;

/// Aggregated enrichment data attached to a diff. Keyed by the component's
/// purl-with-version (e.g. `pkg:npm/axios@1.14.1`) so renderers can look up
/// per-component findings without re-iterating over the changeset.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Enrichment {
    /// Map of `purl@version` → list of advisory IDs (e.g. GHSA-..., CVE-...).
    /// Components with no findings are absent from the map (never present with
    /// an empty Vec) so renderers can use `vulns_for(...).is_empty()` as the
    /// "show this row?" predicate.
    pub vulns: HashMap<String, Vec<String>>,
    /// Newly added components whose names look suspiciously close to a popular
    /// package. Always informational — never trips fail-on.
    pub typosquats: Vec<TyposquatFinding>,
}

impl Enrichment {
    pub fn vulns_for(&self, purl: Option<&str>) -> &[String] {
        match purl {
            Some(p) => self.vulns.get(p).map(Vec::as_slice).unwrap_or(&[]),
            None => &[],
        }
    }

    pub fn has_findings(&self) -> bool {
        !self.vulns.is_empty() || !self.typosquats.is_empty()
    }
}
