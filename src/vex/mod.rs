//! VEX (Vulnerability Exploitability eXchange) consumption (v0.9, Phase G).
//!
//! Loads VEX statements from one or more user-supplied files and exposes a
//! matcher that maps each statement to bomdrift findings by
//! `(vuln_id_or_alias, product_purl)`. Two formats are auto-detected per
//! file:
//!
//! - **OpenVEX 0.2.0** (preferred): JSON-LD doc with a top-level
//!   `@context: "https://openvex.dev/ns/..."` key and a `statements[]`
//!   array.
//! - **CycloneDX VEX 1.6**: CycloneDX-shaped doc with `bomFormat:
//!   "CycloneDX"` and a `vulnerabilities[]` array.
//!
//! ## Match keys
//!
//! - For OSV / CVE / GHSA findings: `(VulnRef.id OR alias, purl_with_version)`.
//! - For bomdrift "synthetic" finding kinds (typosquat, version-jump,
//!   maintainer-age, license-violation): `(synthetic_id, purl_with_version)`
//!   where `synthetic_id` follows the convention
//!   `bomdrift.<kind>:<purl>:<discriminator>` documented in
//!   `docs/src/vex.md`.
//!
//! ## Conflict resolution
//!
//! When multiple files contain a statement for the same `(vuln_id,
//! product)`, the first-loaded statement wins. Documented as
//! first-write-wins so users layering policy + project-level VEX know
//! which file takes precedence.

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::Serialize;

mod apply;
mod cyclonedx_vex;
mod openvex;
pub mod synthetic_id;

pub use apply::apply;
pub use synthetic_id::{SyntheticFindingKind, parse_synthetic_id};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VexFormat {
    OpenVex,
    CycloneDxVex,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VexStatus {
    NotAffected,
    Affected,
    Fixed,
    UnderInvestigation,
}

impl VexStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            VexStatus::NotAffected => "not_affected",
            VexStatus::Affected => "affected",
            VexStatus::Fixed => "fixed",
            VexStatus::UnderInvestigation => "under_investigation",
        }
    }

    pub fn from_openvex(s: &str) -> Option<Self> {
        match s {
            "not_affected" => Some(Self::NotAffected),
            "affected" => Some(Self::Affected),
            "fixed" => Some(Self::Fixed),
            "under_investigation" => Some(Self::UnderInvestigation),
            _ => None,
        }
    }

    /// CycloneDX VEX `analysis.state` mapping.
    pub fn from_cyclonedx_state(s: &str) -> Option<Self> {
        match s {
            "not_affected" | "resolved" | "resolved_with_pedigree" | "false_positive" => {
                Some(Self::NotAffected)
            }
            "exploitable" => Some(Self::Affected),
            "in_triage" => Some(Self::UnderInvestigation),
            _ => None,
        }
    }
}

/// A single VEX statement after format normalization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VexStatement {
    pub vuln_id: String,
    pub products: Vec<String>,
    pub status: VexStatus,
    pub justification: Option<String>,
    pub status_notes: Option<String>,
}

/// Load every `path` in order and return the merged statement list.
/// First-write-wins on `(vuln_id, product)` collisions across files.
pub fn load(paths: &[PathBuf]) -> Result<Vec<VexStatement>> {
    let mut out: Vec<VexStatement> = Vec::new();
    let mut seen: HashMap<(String, String), usize> = HashMap::new();
    for path in paths {
        let body = fs::read_to_string(path)
            .with_context(|| format!("reading VEX file: {}", path.display()))?;
        let value: serde_json::Value = serde_json::from_str(&body)
            .with_context(|| format!("parsing VEX JSON: {}", path.display()))?;
        let format = detect_format(&value).ok_or_else(|| {
            anyhow::anyhow!(
                "could not detect VEX format (expected OpenVEX `@context` or CycloneDX `bomFormat`): {}",
                path.display()
            )
        })?;
        let stmts = match format {
            VexFormat::OpenVex => openvex::parse(&value, path)?,
            VexFormat::CycloneDxVex => cyclonedx_vex::parse(&value, path)?,
        };
        for s in stmts {
            for product in &s.products {
                let key = (s.vuln_id.clone(), product.clone());
                seen.entry(key).or_insert_with(|| {
                    let idx = out.len();
                    out.push(VexStatement {
                        vuln_id: s.vuln_id.clone(),
                        products: vec![product.clone()],
                        status: s.status,
                        justification: s.justification.clone(),
                        status_notes: s.status_notes.clone(),
                    });
                    idx
                });
            }
            // Statement with empty products list (broad statement) — keep
            // once with empty products vec; matchers ignore unless future
            // logic uses it. For now, drop.
            if s.products.is_empty() {
                let key = (s.vuln_id.clone(), String::new());
                seen.entry(key).or_insert_with(|| {
                    let idx = out.len();
                    out.push(s.clone());
                    idx
                });
            }
        }
    }
    Ok(out)
}

fn detect_format(value: &serde_json::Value) -> Option<VexFormat> {
    if let Some(ctx) = value.get("@context").and_then(|v| v.as_str())
        && ctx.contains("openvex.dev/ns")
    {
        return Some(VexFormat::OpenVex);
    }
    if value.get("bomFormat").and_then(|v| v.as_str()) == Some("CycloneDX")
        && value
            .get("vulnerabilities")
            .and_then(|v| v.as_array())
            .is_some()
    {
        return Some(VexFormat::CycloneDxVex);
    }
    None
}

/// What the VEX matcher decided to do with a statement+finding pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VexEffect {
    /// Drop the finding entirely (status `not_affected` or `fixed`).
    Suppress {
        status: VexStatus,
        justification: Option<String>,
    },
    /// Keep the finding but annotate it (`under_investigation` /
    /// `affected`).
    Annotate {
        status: VexStatus,
        justification: Option<String>,
    },
}

impl VexEffect {
    pub fn is_suppress(&self) -> bool {
        matches!(self, VexEffect::Suppress { .. })
    }

    pub fn status(&self) -> VexStatus {
        match self {
            VexEffect::Suppress { status, .. } | VexEffect::Annotate { status, .. } => *status,
        }
    }

    pub fn justification(&self) -> Option<&str> {
        match self {
            VexEffect::Suppress { justification, .. }
            | VexEffect::Annotate { justification, .. } => justification.as_deref(),
        }
    }
}

/// In-memory matcher — group statements by vuln_id for O(1) lookup, with
/// an additional product-keyed inner map for product-specific resolution.
pub struct VexIndex {
    /// `vuln_id -> Vec<statement>` (preserved order from load()).
    by_vuln: HashMap<String, Vec<VexStatement>>,
}

impl VexIndex {
    pub fn build(stmts: Vec<VexStatement>) -> Self {
        let mut by_vuln: HashMap<String, Vec<VexStatement>> = HashMap::new();
        for s in stmts {
            by_vuln.entry(s.vuln_id.clone()).or_default().push(s);
        }
        Self { by_vuln }
    }

    pub fn is_empty(&self) -> bool {
        self.by_vuln.is_empty()
    }

    /// Resolve a `(vuln_id_candidates, product_purl)` pair to an effect.
    /// `candidates` is the ordered list `[primary_id, alias1, alias2, ...]`
    /// the caller will try; the first matching statement wins.
    pub fn resolve<'a, I>(&self, candidates: I, product: &str) -> Option<VexEffect>
    where
        I: IntoIterator<Item = &'a str>,
    {
        for cand in candidates {
            let Some(stmts) = self.by_vuln.get(cand) else {
                continue;
            };
            for s in stmts {
                if s.products.iter().any(|p| product_matches(p, product)) {
                    return Some(effect_for(s));
                }
            }
        }
        None
    }
}

/// Product matching: exact equality, OR a versionless product matches a
/// versioned finding-product (e.g. statement `pkg:npm/foo` matches
/// finding `pkg:npm/foo@1.2.3`). The reverse is NOT permitted — a
/// statement with a specific version must not match a different version.
fn product_matches(stmt_product: &str, finding_product: &str) -> bool {
    if stmt_product == finding_product {
        return true;
    }
    if !stmt_product.contains('@')
        && let Some(stripped) = finding_product.split_once('@')
        && stripped.0 == stmt_product
    {
        return true;
    }
    false
}

fn effect_for(s: &VexStatement) -> VexEffect {
    match s.status {
        VexStatus::NotAffected | VexStatus::Fixed => VexEffect::Suppress {
            status: s.status,
            justification: s.justification.clone(),
        },
        VexStatus::Affected | VexStatus::UnderInvestigation => VexEffect::Annotate {
            status: s.status,
            justification: s.justification.clone(),
        },
    }
}

/// Attached VEX annotation kept on a finding when status is `affected` or
/// `under_investigation`. Renderers surface these as inline badges.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VexAnnotation {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub justification: Option<String>,
}

impl VexAnnotation {
    pub fn from_effect(effect: &VexEffect) -> Self {
        Self {
            status: effect.status().as_str().to_string(),
            justification: effect.justification().map(str::to_string),
        }
    }
}

mod emit;
pub use emit::{EmitOptions, emit};

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::todo,
        clippy::unimplemented
    )]
    use super::*;
    use std::io::Write as _;

    fn write_tmp(name: &str, body: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "bomdrift-vex-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(name);
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(body.as_bytes()).unwrap();
        path
    }

    #[test]
    fn load_openvex_basic() {
        let body = r#"{
            "@context": "https://openvex.dev/ns/v0.2.0",
            "@id": "https://x/y",
            "author": "test",
            "timestamp": "2026-01-01T00:00:00Z",
            "version": 1,
            "statements": [
                {
                    "vulnerability": {"name": "CVE-2024-1111"},
                    "products": [{"@id": "pkg:npm/foo@1.0.0"}],
                    "status": "not_affected",
                    "justification": "vulnerable_code_not_present"
                },
                {
                    "vulnerability": {"name": "CVE-2024-2222"},
                    "products": ["pkg:npm/bar@2.0.0"],
                    "status": "under_investigation"
                }
            ]
        }"#;
        let p = write_tmp("openvex.json", body);
        let stmts = load(&[p]).unwrap();
        assert_eq!(stmts.len(), 2);
        assert_eq!(stmts[0].vuln_id, "CVE-2024-1111");
        assert_eq!(stmts[0].status, VexStatus::NotAffected);
        assert_eq!(
            stmts[0].justification.as_deref(),
            Some("vulnerable_code_not_present")
        );
        assert_eq!(stmts[1].status, VexStatus::UnderInvestigation);
    }

    #[test]
    fn load_cyclonedx_vex_basic() {
        let body = r#"{
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "vulnerabilities": [
                {
                    "id": "CVE-2024-3333",
                    "affects": [{"ref": "pkg:npm/baz@3.0.0"}],
                    "analysis": {
                        "state": "not_affected",
                        "justification": "code_not_reachable",
                        "detail": "see PR #99"
                    }
                },
                {
                    "id": "CVE-2024-4444",
                    "affects": [{"ref": "pkg:npm/qux@4.0.0"}],
                    "analysis": { "state": "exploitable" }
                }
            ]
        }"#;
        let p = write_tmp("cdx.json", body);
        let stmts = load(&[p]).unwrap();
        assert_eq!(stmts.len(), 2);
        assert_eq!(stmts[0].vuln_id, "CVE-2024-3333");
        assert_eq!(stmts[0].status, VexStatus::NotAffected);
        assert_eq!(stmts[0].status_notes.as_deref(), Some("see PR #99"));
        assert_eq!(stmts[1].status, VexStatus::Affected);
    }

    #[test]
    fn unknown_format_errors_with_path() {
        let p = write_tmp("bad.json", r#"{"foo":"bar"}"#);
        let err = load(std::slice::from_ref(&p)).unwrap_err().to_string();
        assert!(err.contains(&p.display().to_string()));
        assert!(err.to_lowercase().contains("vex format") || err.contains("OpenVEX"));
    }

    #[test]
    fn first_write_wins_across_multiple_files() {
        let a = write_tmp(
            "a.json",
            r#"{
                "@context": "https://openvex.dev/ns/v0.2.0",
                "statements": [{"vulnerability": {"name": "CVE-A"}, "products": [{"@id": "pkg:npm/x@1.0.0"}], "status": "not_affected"}]
            }"#,
        );
        let b = write_tmp(
            "b.json",
            r#"{
                "@context": "https://openvex.dev/ns/v0.2.0",
                "statements": [{"vulnerability": {"name": "CVE-A"}, "products": [{"@id": "pkg:npm/x@1.0.0"}], "status": "affected"}]
            }"#,
        );
        let stmts = load(&[a, b]).unwrap();
        assert_eq!(stmts.len(), 1);
        assert_eq!(stmts[0].status, VexStatus::NotAffected);
    }

    #[test]
    fn matcher_resolves_by_alias() {
        let stmt = VexStatement {
            vuln_id: "CVE-2024-X".into(),
            products: vec!["pkg:npm/foo@1.0.0".into()],
            status: VexStatus::NotAffected,
            justification: Some("vulnerable_code_not_present".into()),
            status_notes: None,
        };
        let idx = VexIndex::build(vec![stmt]);
        // Primary is GHSA, alias is CVE-2024-X — match through alias.
        let cands = ["GHSA-abc", "CVE-2024-X"];
        let effect = idx
            .resolve(cands.iter().copied(), "pkg:npm/foo@1.0.0")
            .expect("matched via alias");
        assert!(effect.is_suppress());
        assert_eq!(effect.status(), VexStatus::NotAffected);
    }

    #[test]
    fn matcher_rejects_mismatched_product() {
        let stmt = VexStatement {
            vuln_id: "CVE-1".into(),
            products: vec!["pkg:npm/foo@1.0.0".into()],
            status: VexStatus::NotAffected,
            justification: None,
            status_notes: None,
        };
        let idx = VexIndex::build(vec![stmt]);
        assert!(idx.resolve(["CVE-1"], "pkg:npm/bar@1.0.0").is_none());
    }

    #[test]
    fn matcher_versionless_product_matches_versioned_finding() {
        let stmt = VexStatement {
            vuln_id: "CVE-1".into(),
            products: vec!["pkg:npm/foo".into()],
            status: VexStatus::Fixed,
            justification: None,
            status_notes: None,
        };
        let idx = VexIndex::build(vec![stmt]);
        let effect = idx.resolve(["CVE-1"], "pkg:npm/foo@9.9.9").unwrap();
        assert!(effect.is_suppress());
    }

    #[test]
    fn under_investigation_annotates_not_suppresses() {
        let stmt = VexStatement {
            vuln_id: "CVE-1".into(),
            products: vec!["pkg:npm/foo@1.0.0".into()],
            status: VexStatus::UnderInvestigation,
            justification: None,
            status_notes: None,
        };
        let idx = VexIndex::build(vec![stmt]);
        let effect = idx.resolve(["CVE-1"], "pkg:npm/foo@1.0.0").unwrap();
        assert!(!effect.is_suppress());
        assert_eq!(effect.status(), VexStatus::UnderInvestigation);
    }

    /// Cover `VexEffect::justification()` for both Suppress and Annotate
    /// variants (kills the 3 mutants on the getter: `replace with None`,
    /// arm-swap, etc.).
    #[test]
    fn vex_effect_justification_returns_inner_for_both_variants() {
        let suppress = VexEffect::Suppress {
            status: VexStatus::NotAffected,
            justification: Some("vulnerable_code_not_present".into()),
        };
        assert_eq!(
            suppress.justification(),
            Some("vulnerable_code_not_present")
        );

        let annotate = VexEffect::Annotate {
            status: VexStatus::Affected,
            justification: Some("see ticket BD-42".into()),
        };
        assert_eq!(annotate.justification(), Some("see ticket BD-42"));

        // None passes through (not coerced to Some("")).
        let suppress_none = VexEffect::Suppress {
            status: VexStatus::Fixed,
            justification: None,
        };
        assert_eq!(suppress_none.justification(), None);
    }

    /// `VexIndex::is_empty` reflects the underlying `by_vuln` map state.
    /// Kills the 2 mutants on `is_empty` (replace-with-true / replace-with-
    /// false).
    #[test]
    fn vex_index_is_empty_tracks_statement_presence() {
        let empty = VexIndex::build(Vec::new());
        assert!(empty.is_empty());

        let stmt = VexStatement {
            vuln_id: "CVE-1".into(),
            products: vec!["pkg:npm/foo@1.0.0".into()],
            status: VexStatus::NotAffected,
            justification: None,
            status_notes: None,
        };
        let populated = VexIndex::build(vec![stmt]);
        assert!(!populated.is_empty());
    }

    /// `detect_format` second arm requires BOTH `bomFormat == "CycloneDX"`
    /// AND a `vulnerabilities` array. Kills the `&& -> ||` mutant at line
    /// 162: with `||`, a doc that has only `bomFormat` (a regular CycloneDX
    /// SBOM with no vulnerabilities) would be misclassified as VEX and
    /// fail the parse loudly later.
    #[test]
    fn detect_format_cyclonedx_requires_vulnerabilities_array() {
        // CycloneDX SBOM with no `vulnerabilities` array — must NOT be
        // detected as CycloneDxVex. load() should error with the unknown-
        // format diagnostic, not try to parse it as VEX.
        let body = r#"{
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "components": [{"name": "foo", "version": "1.0.0"}]
        }"#;
        let p = write_tmp("sbom_not_vex.json", body);
        let err = load(std::slice::from_ref(&p)).unwrap_err().to_string();
        assert!(
            err.to_lowercase().contains("vex format") || err.contains("OpenVEX"),
            "expected unknown-format error, got: {err}"
        );

        // `bomFormat` present, `vulnerabilities` present-but-wrong-type
        // (object, not array) — also must NOT match.
        let body2 = r#"{
            "bomFormat": "CycloneDX",
            "vulnerabilities": {"id": "CVE-X"}
        }"#;
        let p2 = write_tmp("sbom_vuln_obj.json", body2);
        let err2 = load(std::slice::from_ref(&p2)).unwrap_err().to_string();
        assert!(
            err2.to_lowercase().contains("vex format") || err2.contains("OpenVEX"),
            "expected unknown-format error, got: {err2}"
        );
    }
}
