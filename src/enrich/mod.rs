//! Risk-signal enrichers. Each runs over a [`crate::diff::ChangeSet`] and produces
//! data that the renderers can pair back to the changed components.
//!
//! v0 ships [`osv`] (CVE lookup via OSV.dev), [`typosquat`] (similarity to
//! popular npm packages), [`version_jump`] (multi-major upgrades), and
//! [`maintainer`] (xz-style young-maintainer signal via the GitHub REST API).
//!
//! New `Enrichment` fields must derive `serde::Serialize` to appear in JSON
//! output (see `crate::render::json`). Every finding type added here MUST
//! keep that contract or the JSON renderer will fail to compile.

pub mod maintainer;
pub mod osv;
pub mod typosquat;
pub mod version_jump;

use std::collections::HashMap;

use serde::Serialize;

use maintainer::MaintainerAgeFinding;
use typosquat::TyposquatFinding;
use version_jump::VersionJumpFinding;

/// Aggregated enrichment data attached to a diff. Keyed by the component's
/// purl-with-version (e.g. `pkg:npm/axios@1.14.1`) so renderers can look up
/// per-component findings without re-iterating over the changeset.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct Enrichment {
    /// Map of `purl@version` → list of advisory IDs (e.g. GHSA-..., CVE-...).
    /// Components with no findings are absent from the map (never present with
    /// an empty Vec) so renderers can use `vulns_for(...).is_empty()` as the
    /// "show this row?" predicate.
    pub vulns: HashMap<String, Vec<String>>,
    /// Newly added components whose names look suspiciously close to a popular
    /// package. Always informational — never trips fail-on.
    pub typosquats: Vec<TyposquatFinding>,
    /// Version-changed components whose major version jumped by 2 or more in a
    /// single diff (e.g. 1.x → 4.x). Always informational — never trips
    /// fail-on.
    pub version_jumps: Vec<VersionJumpFinding>,
    /// Newly added components whose top GitHub contributor's first commit is
    /// younger than [`maintainer::YOUNG_MAINTAINER_DAYS`]. The xz/Jia Tan
    /// pattern. Always informational — never trips fail-on.
    pub maintainer_age: Vec<MaintainerAgeFinding>,
}

impl Enrichment {
    pub fn vulns_for(&self, purl: Option<&str>) -> &[String] {
        match purl {
            Some(p) => self.vulns.get(p).map(Vec::as_slice).unwrap_or(&[]),
            None => &[],
        }
    }

    pub fn has_findings(&self) -> bool {
        !self.vulns.is_empty()
            || !self.typosquats.is_empty()
            || !self.version_jumps.is_empty()
            || !self.maintainer_age.is_empty()
    }
}
