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

pub mod cache;
pub mod maintainer;
pub mod osv;
pub mod typosquat;
pub mod version_jump;

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use maintainer::MaintainerAgeFinding;
use typosquat::TyposquatFinding;
use version_jump::VersionJumpFinding;

/// Aggregated enrichment data attached to a diff. Keyed by the component's
/// purl-with-version (e.g. `pkg:npm/axios@1.14.1`) so renderers can look up
/// per-component findings without re-iterating over the changeset.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct Enrichment {
    /// Map of `purl@version` → list of advisory references with severity.
    /// Components with no findings are absent from the map (never present
    /// with an empty Vec) so renderers can use `vulns_for(...).is_empty()`
    /// as the "show this row?" predicate.
    ///
    /// **Shape change in v0.3:** values are now [`VulnRef`] objects (id +
    /// severity) instead of bare advisory ID strings. JSON consumers that
    /// expected `"vulns": {"<purl>": ["GHSA-..."]}` need to migrate to
    /// `"vulns": {"<purl>": [{"id": "GHSA-...", "severity": "HIGH"}]}`.
    pub vulns: HashMap<String, Vec<VulnRef>>,
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
    pub fn vulns_for(&self, purl: Option<&str>) -> &[VulnRef] {
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

/// A single advisory reference attached to a vulnerable component, with the
/// best-known severity bucket. Built by [`osv::enrich`] from the
/// `/v1/querybatch` advisory IDs plus per-advisory `/v1/vulns/{id}` lookups.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VulnRef {
    /// Stable advisory identifier (`GHSA-…`, `CVE-…`, `MAL-…`, `OSV-…`).
    pub id: String,
    /// Severity bucket, defaulting to [`Severity::None`] when no severity
    /// could be resolved (network failure, advisory predates GHSA tagging,
    /// CVSS-only severity not yet parsed — see [`Severity`] doc comment).
    pub severity: Severity,
}

/// Severity bucket for an advisory. Ordered low-to-high so `>= Severity::High`
/// reads like its English meaning ("at least high"). Renderers map this back
/// to per-format conventions (SARIF `level`, ANSI color, markdown badge).
///
/// ## Sources, in priority order
///
/// 1. `database_specific.severity` from the OSV `/v1/vulns/{id}` response —
///    GHSA's text label (`LOW|MODERATE|HIGH|CRITICAL`). Most reliable for the
///    GHSA-prefixed advisories that dominate npm/PyPI/Maven traffic.
///    `MODERATE` maps to [`Severity::Medium`] so we keep a single
///    user-facing vocabulary across renderers.
/// 2. Highest `severity[].score` of `type == "CVSS_V3"` parsed to a base
///    score. Bucketing follows NVD: ≥9.0 → Critical, ≥7.0 → High, ≥4.0 →
///    Medium, ≥0.1 → Low. (CVSS vector parsing lands in v0.4; v0.3 only
///    consumes the database_specific text label and falls back to
///    [`Severity::None`] when missing.)
/// 3. [`Severity::None`] otherwise. The advisory still surfaces; it just
///    doesn't trip `--fail-on critical-cve`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    /// No severity available (offline, no GHSA tag, etc). Renders as `NONE`.
    None,
    Low,
    /// GHSA's `MODERATE` collapses to this bucket.
    Medium,
    High,
    Critical,
}

impl Severity {
    /// Parse GHSA's text severity label as it appears in OSV's
    /// `database_specific.severity` field. `MODERATE` is GHSA's spelling for
    /// what the rest of the industry calls Medium. Comparison is
    /// case-insensitive so consumers don't fail on `Critical` vs `CRITICAL`.
    pub fn from_ghsa_label(label: &str) -> Self {
        match label.trim().to_ascii_uppercase().as_str() {
            "CRITICAL" => Self::Critical,
            "HIGH" => Self::High,
            "MEDIUM" | "MODERATE" => Self::Medium,
            "LOW" => Self::Low,
            _ => Self::None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Critical => "CRITICAL",
            Self::High => "HIGH",
            Self::Medium => "MEDIUM",
            Self::Low => "LOW",
            Self::None => "NONE",
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ghsa_label_parses_canonical_forms() {
        assert_eq!(Severity::from_ghsa_label("CRITICAL"), Severity::Critical);
        assert_eq!(Severity::from_ghsa_label("HIGH"), Severity::High);
        assert_eq!(Severity::from_ghsa_label("MODERATE"), Severity::Medium);
        assert_eq!(Severity::from_ghsa_label("MEDIUM"), Severity::Medium);
        assert_eq!(Severity::from_ghsa_label("LOW"), Severity::Low);
    }

    #[test]
    fn ghsa_label_is_case_insensitive_and_trim_tolerant() {
        assert_eq!(Severity::from_ghsa_label(" Critical "), Severity::Critical);
        assert_eq!(Severity::from_ghsa_label("moderate"), Severity::Medium);
    }

    #[test]
    fn unknown_label_falls_back_to_none() {
        assert_eq!(Severity::from_ghsa_label(""), Severity::None);
        assert_eq!(Severity::from_ghsa_label("urgent"), Severity::None);
    }

    #[test]
    fn severity_ordering_low_to_high() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::None);
    }

    #[test]
    fn severity_serializes_as_uppercase_string() {
        let s = serde_json::to_string(&Severity::High).unwrap();
        assert_eq!(s, "\"HIGH\"");
    }
}
