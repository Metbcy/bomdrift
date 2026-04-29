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
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Serialize;

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
            VexFormat::OpenVex => parse_openvex(&value, path)?,
            VexFormat::CycloneDxVex => parse_cyclonedx_vex(&value, path)?,
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

fn parse_openvex(value: &serde_json::Value, path: &Path) -> Result<Vec<VexStatement>> {
    let stmts = value
        .get("statements")
        .and_then(|v| v.as_array())
        .ok_or_else(|| {
            anyhow::anyhow!("OpenVEX doc missing `statements` array: {}", path.display())
        })?;
    let mut out = Vec::with_capacity(stmts.len());
    for s in stmts {
        let vuln_id = s
            .get("vulnerability")
            .and_then(|v| v.get("name"))
            .and_then(|v| v.as_str())
            .or_else(|| {
                // Older OpenVEX drafts allowed `vulnerability` as a bare string.
                s.get("vulnerability").and_then(|v| v.as_str())
            })
            .unwrap_or("")
            .to_string();
        if vuln_id.is_empty() {
            continue;
        }
        let status_raw = s.get("status").and_then(|v| v.as_str()).unwrap_or("");
        let Some(status) = VexStatus::from_openvex(status_raw) else {
            continue;
        };
        let mut products: Vec<String> = Vec::new();
        if let Some(arr) = s.get("products").and_then(|v| v.as_array()) {
            for p in arr {
                if let Some(s) = p.as_str() {
                    products.push(s.to_string());
                } else if let Some(id) = p.get("@id").and_then(|v| v.as_str()) {
                    products.push(id.to_string());
                } else if let Some(id) = p.get("id").and_then(|v| v.as_str()) {
                    products.push(id.to_string());
                }
            }
        }
        let justification = s
            .get("justification")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        let status_notes = s
            .get("status_notes")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        out.push(VexStatement {
            vuln_id,
            products,
            status,
            justification,
            status_notes,
        });
    }
    Ok(out)
}

fn parse_cyclonedx_vex(value: &serde_json::Value, path: &Path) -> Result<Vec<VexStatement>> {
    let vulns = value
        .get("vulnerabilities")
        .and_then(|v| v.as_array())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "CycloneDX VEX missing `vulnerabilities` array: {}",
                path.display()
            )
        })?;
    let mut out = Vec::with_capacity(vulns.len());
    for v in vulns {
        let vuln_id = v
            .get("id")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        if vuln_id.is_empty() {
            continue;
        }
        let analysis = v.get("analysis");
        let state = analysis
            .and_then(|a| a.get("state"))
            .and_then(|x| x.as_str())
            .unwrap_or("");
        let Some(status) = VexStatus::from_cyclonedx_state(state) else {
            continue;
        };
        let mut products: Vec<String> = Vec::new();
        if let Some(arr) = v.get("affects").and_then(|v| v.as_array()) {
            for a in arr {
                if let Some(r) = a.get("ref").and_then(|x| x.as_str()) {
                    products.push(r.to_string());
                }
            }
        }
        let justification = analysis
            .and_then(|a| a.get("justification"))
            .and_then(|x| x.as_str())
            .map(str::to_string);
        let status_notes = analysis
            .and_then(|a| a.get("detail"))
            .and_then(|x| x.as_str())
            .map(str::to_string);
        out.push(VexStatement {
            vuln_id,
            products,
            status,
            justification,
            status_notes,
        });
    }
    Ok(out)
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

/// Synthetic IDs bomdrift uses for non-CVE finding kinds. The same scheme
/// is used by `--emit-vex` (Phase H) and `--vex` (this module) so users
/// can write `not_affected` statements against typosquat / version-jump /
/// maintainer-age / license-violation findings.
pub mod synthetic_id {
    use crate::enrich::LicenseViolation;
    use crate::enrich::maintainer::MaintainerAgeFinding;
    use crate::enrich::typosquat::TyposquatFinding;
    use crate::enrich::version_jump::VersionJumpFinding;

    pub fn typosquat(f: &TyposquatFinding) -> String {
        let purl = f.component.purl.as_deref().unwrap_or(&f.component.name);
        format!("bomdrift.typosquat:{purl}:{}", f.closest)
    }

    pub fn version_jump(f: &VersionJumpFinding) -> String {
        let purl = f.after.purl.as_deref().unwrap_or(&f.after.name);
        format!(
            "bomdrift.version-jump:{purl}:{}->{}",
            f.before_major, f.after_major
        )
    }

    pub fn maintainer_age(f: &MaintainerAgeFinding) -> String {
        let purl = f.component.purl.as_deref().unwrap_or(&f.component.name);
        format!("bomdrift.young-maintainer:{purl}:{}", f.top_contributor)
    }

    pub fn license_violation(v: &LicenseViolation) -> String {
        let purl = v.component.purl.as_deref().unwrap_or(&v.component.name);
        format!("bomdrift.license-violation:{purl}:{}", v.license)
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

/// Apply the VEX index to an `Enrichment`. Suppresses findings with
/// `not_affected` / `fixed` statements and attaches annotations to
/// findings with `affected` / `under_investigation` statements. Returns
/// the count of suppressed findings (set as `vex_suppressed_count`).
pub fn apply(enrichment: &mut crate::enrich::Enrichment, idx: &VexIndex) {
    if idx.is_empty() {
        return;
    }
    let mut suppressed: usize = 0;

    // ---- vulns ----
    let mut vulns = std::mem::take(&mut enrichment.vulns);
    for (purl, refs) in vulns.iter_mut() {
        refs.retain(|v| {
            let mut cands: Vec<&str> = vec![v.id.as_str()];
            cands.extend(v.aliases.iter().map(String::as_str));
            match idx.resolve(cands.iter().copied(), purl) {
                Some(effect) => {
                    if effect.is_suppress() {
                        suppressed += 1;
                        false
                    } else {
                        let key = format!("cve:{purl}:{}", v.id);
                        enrichment
                            .vex_annotations
                            .insert(key, VexAnnotation::from_effect(&effect));
                        true
                    }
                }
                None => true,
            }
        });
    }
    vulns.retain(|_, refs| !refs.is_empty());
    enrichment.vulns = vulns;

    // ---- typosquats ----
    let typos = std::mem::take(&mut enrichment.typosquats);
    enrichment.typosquats = typos
        .into_iter()
        .filter(|f| {
            let purl = f.component.purl.clone().unwrap_or_default();
            let id = synthetic_id::typosquat(f);
            match idx.resolve([id.as_str()], &purl) {
                Some(effect) => {
                    if effect.is_suppress() {
                        suppressed += 1;
                        false
                    } else {
                        enrichment
                            .vex_annotations
                            .insert(id, VexAnnotation::from_effect(&effect));
                        true
                    }
                }
                None => true,
            }
        })
        .collect();

    // ---- version_jumps ----
    let vjs = std::mem::take(&mut enrichment.version_jumps);
    enrichment.version_jumps = vjs
        .into_iter()
        .filter(|f| {
            let purl = f.after.purl.clone().unwrap_or_default();
            let id = synthetic_id::version_jump(f);
            match idx.resolve([id.as_str()], &purl) {
                Some(effect) => {
                    if effect.is_suppress() {
                        suppressed += 1;
                        false
                    } else {
                        enrichment
                            .vex_annotations
                            .insert(id, VexAnnotation::from_effect(&effect));
                        true
                    }
                }
                None => true,
            }
        })
        .collect();

    // ---- maintainer_age ----
    let ma = std::mem::take(&mut enrichment.maintainer_age);
    enrichment.maintainer_age = ma
        .into_iter()
        .filter(|f| {
            let purl = f.component.purl.clone().unwrap_or_default();
            let id = synthetic_id::maintainer_age(f);
            match idx.resolve([id.as_str()], &purl) {
                Some(effect) => {
                    if effect.is_suppress() {
                        suppressed += 1;
                        false
                    } else {
                        enrichment
                            .vex_annotations
                            .insert(id, VexAnnotation::from_effect(&effect));
                        true
                    }
                }
                None => true,
            }
        })
        .collect();

    // ---- license_violations ----
    let lv = std::mem::take(&mut enrichment.license_violations);
    enrichment.license_violations = lv
        .into_iter()
        .filter(|v| {
            let purl = v.component.purl.clone().unwrap_or_default();
            let id = synthetic_id::license_violation(v);
            match idx.resolve([id.as_str()], &purl) {
                Some(effect) => {
                    if effect.is_suppress() {
                        suppressed += 1;
                        false
                    } else {
                        enrichment
                            .vex_annotations
                            .insert(id, VexAnnotation::from_effect(&effect));
                        true
                    }
                }
                None => true,
            }
        })
        .collect();

    enrichment.vex_suppressed_count += suppressed;
}

#[cfg(test)]
mod tests {
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
}
