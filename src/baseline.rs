//! Baseline suppression: filter out findings already present in a previously
//! captured `--output json` snapshot.
//!
//! ## Why
//!
//! Adopting bomdrift on a project with an existing dependency set means the
//! first PR comment lists every pre-existing CVE / typosquat / multi-major
//! jump / young-maintainer hit, drowning legitimate review signal. A baseline
//! file lets the team accept the existing state in one shot ("we know about
//! these") and surface only what changed in subsequent PRs.
//!
//! ## Match keys
//!
//! Conservative — a finding only suppresses when it's exactly the same as
//! something in the baseline. Drift causes the new instance to surface:
//!
//! - **CVE / advisory** — `(purl_with_version, advisory_id)`. A new CVE on
//!   the same component still surfaces; the same CVE on a new component
//!   still surfaces; the same CVE on the same component at a new version
//!   still surfaces.
//! - **Typosquat** — `(purl_with_version, closest)`. Same suspicious name
//!   at the same version IS suppressed; renaming the legit reference
//!   surfaces it again (rare in practice but defensible).
//! - **Version-jump** — `(after.purl_with_version, before_major, after_major)`.
//!   Identical jump suppressed; further jumps surface.
//! - **Young-maintainer** — `(component.purl_with_version, top_contributor)`.
//!   Same dep, same flagged maintainer suppressed; a new maintainer takes
//!   over → resurfaced.
//!
//! ## Format
//!
//! The baseline file is exactly the `bomdrift diff --output json` output:
//! `{ "changes": {…}, "enrichment": {…} }`. Teams capture it once on main,
//! commit it (or stash in CI artifacts), and pass `--baseline path.json`
//! to subsequent diffs. JSON is the canonical baseline shape; SARIF / markdown
//! / terminal aren't reversible inputs.

use std::collections::HashSet;
use std::path::Path;

use anyhow::{Context, Result};

use crate::diff::ChangeSet;
use crate::enrich::Enrichment;

/// Parsed baseline content: precomputed match-key sets ready for O(1) lookup
/// during suppression. Built once per `bomdrift diff --baseline …` invocation.
#[derive(Debug, Default)]
pub struct Baseline {
    vuln_keys: HashSet<(String, String)>,
    typosquat_keys: HashSet<(String, String)>,
    version_jump_keys: HashSet<(String, u32, u32)>,
    young_maintainer_keys: HashSet<(String, String)>,
}

impl Baseline {
    pub fn load(path: &Path) -> Result<Self> {
        let body = std::fs::read_to_string(path)
            .with_context(|| format!("reading baseline file: {}", path.display()))?;
        let value: serde_json::Value = serde_json::from_str(&body)
            .with_context(|| format!("parsing baseline JSON: {}", path.display()))?;
        Ok(Self::from_value(&value))
    }

    /// Build a `Baseline` from an already-parsed bomdrift JSON document. Every
    /// extraction step is best-effort — a baseline missing the `enrichment`
    /// or `changes` block produces an empty key set for that section, never
    /// an error. (Pinning the parser to a strict schema would force users to
    /// regenerate baselines on every minor version bump; not worth it.)
    pub fn from_value(value: &serde_json::Value) -> Self {
        let mut out = Self::default();

        let enrichment = &value["enrichment"];

        // vulns: { "<purl@version>": [{ "id": "...", "severity": "..." }, ...] }
        if let Some(vulns) = enrichment["vulns"].as_object() {
            for (purl, list) in vulns {
                if let Some(arr) = list.as_array() {
                    for entry in arr {
                        if let Some(id) = entry["id"].as_str() {
                            out.vuln_keys.insert((purl.clone(), id.to_string()));
                        }
                    }
                }
            }
        }

        // typosquats: [{ "component": { "purl": ... }, "closest": "...", "score": ... }, ...]
        if let Some(arr) = enrichment["typosquats"].as_array() {
            for entry in arr {
                let purl = entry["component"]["purl"].as_str().unwrap_or("");
                let closest = entry["closest"].as_str().unwrap_or("");
                if !purl.is_empty() && !closest.is_empty() {
                    out.typosquat_keys
                        .insert((purl.to_string(), closest.to_string()));
                }
            }
        }

        // version_jumps: [{ "after": { "purl": ... }, "before_major": N, "after_major": M }]
        if let Some(arr) = enrichment["version_jumps"].as_array() {
            for entry in arr {
                let purl = entry["after"]["purl"].as_str().unwrap_or("");
                let before = entry["before_major"].as_u64().unwrap_or(0) as u32;
                let after = entry["after_major"].as_u64().unwrap_or(0) as u32;
                if !purl.is_empty() {
                    out.version_jump_keys
                        .insert((purl.to_string(), before, after));
                }
            }
        }

        // maintainer_age: [{ "component": { "purl": ... }, "top_contributor": "..." }]
        if let Some(arr) = enrichment["maintainer_age"].as_array() {
            for entry in arr {
                let purl = entry["component"]["purl"].as_str().unwrap_or("");
                let contrib = entry["top_contributor"].as_str().unwrap_or("");
                if !purl.is_empty() && !contrib.is_empty() {
                    out.young_maintainer_keys
                        .insert((purl.to_string(), contrib.to_string()));
                }
            }
        }

        out
    }

    /// True when this baseline contains zero suppressible entries (e.g. an
    /// empty file or a baseline with `{"changes": {…}}` only). Lets callers
    /// short-circuit the suppression pass cheaply.
    pub fn is_empty(&self) -> bool {
        self.vuln_keys.is_empty()
            && self.typosquat_keys.is_empty()
            && self.version_jump_keys.is_empty()
            && self.young_maintainer_keys.is_empty()
    }
}

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
    e.vulns.retain(|purl, refs| {
        refs.retain(|r| !baseline.vuln_keys.contains(&(purl.clone(), r.id.clone())));
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enrich::typosquat::TyposquatFinding;
    use crate::enrich::version_jump::VersionJumpFinding;
    use crate::enrich::{Severity, VulnRef};
    use crate::model::{Component, Ecosystem, Relationship};
    use serde_json::json;

    fn comp(purl: &str) -> Component {
        Component {
            name: "x".into(),
            version: "1.0".into(),
            ecosystem: Ecosystem::Npm,
            purl: Some(purl.into()),
            licenses: Vec::new(),
            supplier: None,
            hashes: Vec::new(),
            relationship: Relationship::Unknown,
            source_url: None,
            bom_ref: None,
        }
    }

    #[test]
    fn empty_baseline_is_a_noop() {
        let baseline = Baseline::default();
        let mut cs = ChangeSet::default();
        let mut e = Enrichment::default();
        e.vulns.insert(
            "pkg:npm/x@1.0".into(),
            vec![VulnRef {
                id: "CVE-1".into(),
                severity: Severity::High,
            }],
        );
        apply(&mut cs, &mut e, &baseline);
        assert_eq!(
            e.vulns.len(),
            1,
            "empty baseline must not suppress anything"
        );
    }

    #[test]
    fn vuln_with_matching_key_is_suppressed() {
        let baseline = Baseline::from_value(&json!({
            "enrichment": {
                "vulns": { "pkg:npm/x@1.0": [{"id": "CVE-1", "severity": "HIGH"}] }
            }
        }));
        let mut cs = ChangeSet::default();
        let mut e = Enrichment::default();
        e.vulns.insert(
            "pkg:npm/x@1.0".into(),
            vec![
                VulnRef {
                    id: "CVE-1".into(),
                    severity: Severity::High,
                },
                VulnRef {
                    id: "CVE-2".into(),
                    severity: Severity::Medium,
                },
            ],
        );
        apply(&mut cs, &mut e, &baseline);
        let remaining = e.vulns.get("pkg:npm/x@1.0").expect("purl entry retained");
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].id, "CVE-2", "only CVE-2 must survive");
    }

    #[test]
    fn purl_drops_when_last_advisory_is_suppressed() {
        let baseline = Baseline::from_value(&json!({
            "enrichment": {
                "vulns": { "pkg:npm/x@1.0": [{"id": "CVE-1", "severity": "HIGH"}] }
            }
        }));
        let mut cs = ChangeSet::default();
        let mut e = Enrichment::default();
        e.vulns.insert(
            "pkg:npm/x@1.0".into(),
            vec![VulnRef {
                id: "CVE-1".into(),
                severity: Severity::High,
            }],
        );
        apply(&mut cs, &mut e, &baseline);
        assert!(
            !e.vulns.contains_key("pkg:npm/x@1.0"),
            "purl with zero remaining advisories must be removed from the map"
        );
    }

    #[test]
    fn typosquat_suppression_matches_on_purl_and_closest() {
        let baseline = Baseline::from_value(&json!({
            "enrichment": {
                "typosquats": [{
                    "component": {"purl": "pkg:npm/plain-crypto-js@4.2.1"},
                    "closest": "crypto-js",
                    "score": 0.95
                }]
            }
        }));
        let mut cs = ChangeSet::default();
        let mut e = Enrichment::default();
        e.typosquats.push(TyposquatFinding {
            component: comp("pkg:npm/plain-crypto-js@4.2.1"),
            closest: "crypto-js".into(),
            score: 0.95,
        });
        e.typosquats.push(TyposquatFinding {
            component: comp("pkg:npm/different@1.0"),
            closest: "real".into(),
            score: 0.93,
        });
        apply(&mut cs, &mut e, &baseline);
        assert_eq!(e.typosquats.len(), 1);
        assert_eq!(
            e.typosquats[0].closest, "real",
            "non-baseline finding survives"
        );
    }

    #[test]
    fn version_jump_suppression_matches_on_purl_and_majors() {
        let baseline = Baseline::from_value(&json!({
            "enrichment": {
                "version_jumps": [{
                    "after": {"purl": "pkg:npm/lib@4.0"},
                    "before_major": 1,
                    "after_major": 4
                }]
            }
        }));
        let mut cs = ChangeSet::default();
        let mut e = Enrichment::default();
        e.version_jumps.push(VersionJumpFinding {
            before: comp("pkg:npm/lib@1.0"),
            after: comp("pkg:npm/lib@4.0"),
            before_major: 1,
            after_major: 4,
        });
        apply(&mut cs, &mut e, &baseline);
        assert!(e.version_jumps.is_empty());
    }

    #[test]
    fn malformed_baseline_yields_empty_keys_not_error() {
        // No `enrichment` block at all — load_value treats missing sections as
        // "no suppression" rather than panicking. Lets users hand-write a
        // baseline scope file with just one section.
        let baseline = Baseline::from_value(&json!({}));
        assert!(baseline.is_empty());
    }
}
