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
///
/// Format: `bomdrift.<kind>:<purl>[:<extra>...]`.
///
/// `<purl>` is either a full Package URL (begins `pkg:`) or, when the
/// component lacks one, the bare component name. Round-tripping via
/// [`super::parse_synthetic_id`] handles both shapes.
pub mod synthetic_id {
    use crate::enrich::LicenseViolation;
    use crate::enrich::maintainer::MaintainerAgeFinding;
    use crate::enrich::registry::{Deprecated, MaintainerSetChanged, RecentlyPublished};
    use crate::enrich::typosquat::TyposquatFinding;
    use crate::enrich::version_jump::VersionJumpFinding;
    use crate::model::Component;

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

    /// License-change finding (same component+version, different license
    /// set). Keyed only by purl — the change set is encoded in the
    /// finding payload, not the synthetic id.
    pub fn license_change(after: &Component) -> String {
        let purl = after.purl.as_deref().unwrap_or(&after.name);
        format!("bomdrift.license-change:{purl}")
    }

    pub fn recently_published(f: &RecentlyPublished) -> String {
        let purl = f.component.purl.as_deref().unwrap_or(&f.component.name);
        format!("bomdrift.recently-published:{purl}")
    }

    pub fn deprecated(f: &Deprecated) -> String {
        let purl = f.component.purl.as_deref().unwrap_or(&f.component.name);
        format!("bomdrift.deprecated:{purl}")
    }

    pub fn maintainer_set_changed(f: &MaintainerSetChanged) -> String {
        let purl = f.after.purl.as_deref().unwrap_or(&f.after.name);
        format!("bomdrift.maintainer-set-changed:{purl}")
    }
}

/// Structured form of a parsed bomdrift synthetic finding id. See
/// [`parse_synthetic_id`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyntheticFindingKind {
    Typosquat {
        purl: String,
        closest: String,
    },
    VersionJump {
        purl: String,
        before: String,
        after: String,
    },
    MaintainerAge {
        purl: String,
        top_contributor: String,
    },
    LicenseChange {
        purl: String,
    },
    LicenseViolation {
        purl: String,
        license: String,
    },
    RecentlyPublished {
        purl: String,
    },
    Deprecated {
        purl: String,
    },
    MaintainerSetChanged {
        purl: String,
    },
}

/// Parse a bomdrift synthetic finding-id back into its structured form.
/// Round-trips against the format emitted by [`synthetic_id`].
///
/// Returns `None` for unrecognized formats — non-bomdrift advisory ids
/// (CVEs, GHSAs), malformed strings, or unknown kind tags.
///
/// The `<purl>` segment may be a full Package URL (`pkg:type/...`) or a
/// bare component name when the source SBOM lacked a purl. Both forms
/// round-trip losslessly.
pub fn parse_synthetic_id(s: &str) -> Option<SyntheticFindingKind> {
    let inner = s.strip_prefix("bomdrift.")?;
    let (kind, rest) = inner.split_once(':')?;
    let (purl, extras) = split_purl_and_extras(rest);
    match kind {
        "typosquat" => {
            if extras.is_empty() {
                return None;
            }
            Some(SyntheticFindingKind::Typosquat {
                purl,
                closest: extras.to_string(),
            })
        }
        "version-jump" => {
            let (before, after) = extras.split_once("->")?;
            if before.is_empty() || after.is_empty() {
                return None;
            }
            Some(SyntheticFindingKind::VersionJump {
                purl,
                before: before.to_string(),
                after: after.to_string(),
            })
        }
        "young-maintainer" => {
            if extras.is_empty() {
                return None;
            }
            Some(SyntheticFindingKind::MaintainerAge {
                purl,
                top_contributor: extras.to_string(),
            })
        }
        "license-violation" => {
            if extras.is_empty() {
                return None;
            }
            Some(SyntheticFindingKind::LicenseViolation {
                purl,
                license: extras.to_string(),
            })
        }
        "license-change" => {
            if !extras.is_empty() {
                return None;
            }
            Some(SyntheticFindingKind::LicenseChange { purl })
        }
        "recently-published" => {
            if !extras.is_empty() {
                return None;
            }
            Some(SyntheticFindingKind::RecentlyPublished { purl })
        }
        "deprecated" => {
            if !extras.is_empty() {
                return None;
            }
            Some(SyntheticFindingKind::Deprecated { purl })
        }
        "maintainer-set-changed" => {
            if !extras.is_empty() {
                return None;
            }
            Some(SyntheticFindingKind::MaintainerSetChanged { purl })
        }
        _ => None,
    }
}

/// Split the `<purl>[:<extra>...]` tail of a synthetic id.
///
/// A Package URL contains exactly one `:` (the `pkg:` scheme separator),
/// so when `rest` starts with `pkg:` we recombine through that first
/// colon and use the next colon as the purl/extras boundary. When the
/// component lacked a purl the emitter substitutes the bare name (no
/// `:` inside), and we split at the first colon.
fn split_purl_and_extras(rest: &str) -> (String, &str) {
    if let Some(after_pkg) = rest.strip_prefix("pkg:") {
        match after_pkg.split_once(':') {
            Some((purl_tail, extras)) => (format!("pkg:{purl_tail}"), extras),
            None => (rest.to_string(), ""),
        }
    } else {
        match rest.split_once(':') {
            Some((name, extras)) => (name.to_string(), extras),
            None => (rest.to_string(), ""),
        }
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

/// Synthesized OpenVEX 0.2.0 doc emission (Phase H). Produces a
/// byte-deterministic JSON-LD doc suitable for downstream consumers.
///
/// Statements come from two sources:
/// - **Baseline-suppressed findings**: rich object-form baseline entries
///   contribute one statement each, with `status` taken from the entry's
///   `vex_status` (default `under_investigation`). Plain string-form
///   baseline entries are NEVER auto-promoted to `not_affected` — to
///   make a `not_affected` claim, the user must opt in by adding
///   `vex_status: "not_affected"` to the baseline entry.
/// - **Un-suppressed findings** in the diff: emit as `affected` with
///   `status_notes` describing the bomdrift finding kind.
pub struct EmitOptions<'a> {
    pub author: &'a str,
    pub default_justification: &'a str,
    pub baseline_entries: &'a [crate::baseline::BaselineEntry],
}

#[derive(Debug, Clone)]
struct EmitStmt {
    vuln_id: String,
    product: String,
    status: VexStatus,
    justification: Option<String>,
    status_notes: Option<String>,
}

/// Build the OpenVEX document body and return it as a serialized
/// pretty-printed JSON string. Statements are sorted by
/// `(vulnerability.name, products[0].@id)` for byte-determinism.
pub fn emit(
    cs: &crate::diff::ChangeSet,
    enrichment: &crate::enrich::Enrichment,
    opts: &EmitOptions<'_>,
) -> String {
    let _ = cs; // reserved for future per-component extension
    let mut stmts: Vec<EmitStmt> = Vec::new();

    // Baseline-suppressed entries: one statement per (id, purl) pair.
    for be in opts.baseline_entries {
        let status = be
            .vex_status
            .as_deref()
            .and_then(VexStatus::from_openvex)
            .unwrap_or(VexStatus::UnderInvestigation);
        let justification = be
            .vex_justification
            .clone()
            .or_else(|| Some(opts.default_justification.to_string()));
        let product = be.purl.clone().unwrap_or_default();
        stmts.push(EmitStmt {
            vuln_id: be.id.clone(),
            product,
            status,
            justification,
            status_notes: be.reason.clone(),
        });
    }

    // Un-suppressed findings: emit as `affected`.
    let mut vuln_keys: Vec<&String> = enrichment.vulns.keys().collect();
    vuln_keys.sort();
    for purl in vuln_keys {
        let mut refs: Vec<&crate::enrich::VulnRef> = enrichment.vulns[purl].iter().collect();
        refs.sort_by(|a, b| a.id.cmp(&b.id));
        for r in refs {
            stmts.push(EmitStmt {
                vuln_id: r.id.clone(),
                product: purl.clone(),
                status: VexStatus::Affected,
                justification: Some(opts.default_justification.to_string()),
                status_notes: Some(format!(
                    "bomdrift finding kind: cve (severity {})",
                    r.severity
                )),
            });
        }
    }
    for f in &enrichment.typosquats {
        let purl = f.component.purl.clone().unwrap_or_default();
        stmts.push(EmitStmt {
            vuln_id: synthetic_id::typosquat(f),
            product: purl,
            status: VexStatus::Affected,
            justification: Some(opts.default_justification.to_string()),
            status_notes: Some(format!(
                "bomdrift finding kind: typosquat (similar to {})",
                f.closest
            )),
        });
    }
    for f in &enrichment.version_jumps {
        let purl = f.after.purl.clone().unwrap_or_default();
        stmts.push(EmitStmt {
            vuln_id: synthetic_id::version_jump(f),
            product: purl,
            status: VexStatus::Affected,
            justification: Some(opts.default_justification.to_string()),
            status_notes: Some(format!(
                "bomdrift finding kind: version-jump ({} -> {})",
                f.before_major, f.after_major
            )),
        });
    }
    for f in &enrichment.maintainer_age {
        let purl = f.component.purl.clone().unwrap_or_default();
        stmts.push(EmitStmt {
            vuln_id: synthetic_id::maintainer_age(f),
            product: purl,
            status: VexStatus::Affected,
            justification: Some(opts.default_justification.to_string()),
            status_notes: Some(format!(
                "bomdrift finding kind: young-maintainer ({} days)",
                f.days_old
            )),
        });
    }
    for v in &enrichment.license_violations {
        let purl = v.component.purl.clone().unwrap_or_default();
        stmts.push(EmitStmt {
            vuln_id: synthetic_id::license_violation(v),
            product: purl,
            status: VexStatus::Affected,
            justification: Some(opts.default_justification.to_string()),
            status_notes: Some(format!(
                "bomdrift finding kind: license-violation ({})",
                v.matched_rule
            )),
        });
    }

    // Sort for byte-determinism.
    stmts.sort_by(|a, b| {
        a.vuln_id
            .cmp(&b.vuln_id)
            .then_with(|| a.product.cmp(&b.product))
    });

    // De-dupe on (vuln_id, product) — the baseline-derived statements
    // take precedence (first-seen-wins after sort).
    let mut seen: std::collections::HashSet<(String, String)> = std::collections::HashSet::new();
    stmts.retain(|s| seen.insert((s.vuln_id.clone(), s.product.clone())));

    let timestamp = crate::clock::format_rfc3339(crate::clock::now());

    // @id: a stable identifier for this emission. Deterministic when
    // SOURCE_DATE_EPOCH is set because timestamp is fixed.
    let id_src = format!("{}#{}", opts.author, timestamp);
    let mut hasher = sha2::Sha256::new();
    use sha2::Digest;
    hasher.update(id_src.as_bytes());
    let digest = hasher.finalize();
    let id_hash: String = digest.iter().take(8).map(|b| format!("{b:02x}")).collect();
    let doc_id = format!("https://bomdrift.example/openvex/{id_hash}");

    let statements_json: Vec<serde_json::Value> = stmts
        .iter()
        .map(|s| {
            let mut obj = serde_json::Map::new();
            obj.insert(
                "vulnerability".into(),
                serde_json::json!({ "name": s.vuln_id }),
            );
            if !s.product.is_empty() {
                obj.insert("products".into(), serde_json::json!([{ "@id": s.product }]));
            }
            obj.insert(
                "status".into(),
                serde_json::Value::String(s.status.as_str().to_string()),
            );
            if let Some(j) = &s.justification
                && matches!(s.status, VexStatus::NotAffected)
            {
                // OpenVEX requires `justification` only for not_affected.
                obj.insert("justification".into(), serde_json::Value::String(j.clone()));
            } else if let Some(j) = &s.justification {
                // Carry as `impact_statement` proxy via `justification`
                // for affected/under_investigation rows is non-standard;
                // store as `status_notes` instead — handled below.
                let _ = j;
            }
            if let Some(n) = &s.status_notes {
                obj.insert("status_notes".into(), serde_json::Value::String(n.clone()));
            }
            serde_json::Value::Object(obj)
        })
        .collect();

    let doc = serde_json::json!({
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": doc_id,
        "author": opts.author,
        "timestamp": timestamp,
        "version": 1,
        "statements": statements_json,
    });
    serde_json::to_string_pretty(&doc).expect("serialize OpenVEX doc")
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

    // ---------- Phase H: emission ----------

    fn pin_clock(secs: i64) -> std::sync::MutexGuard<'static, ()> {
        let lock = crate::clock::test_env_lock();
        // SAFETY: env mutations are serialized by the returned mutex
        // guard; the caller must hold it for the duration of the test.
        unsafe {
            std::env::set_var("SOURCE_DATE_EPOCH", secs.to_string());
        }
        lock
    }
    fn unpin_clock() {
        unsafe {
            std::env::remove_var("SOURCE_DATE_EPOCH");
        }
    }

    #[test]
    fn emission_roundtrip_via_loader() {
        let _lock = pin_clock(1_700_000_000);
        let cs = crate::diff::ChangeSet::default();
        let e = crate::enrich::Enrichment::default();
        let entries = vec![crate::baseline::BaselineEntry {
            id: "GHSA-x-y-z".into(),
            purl: Some("pkg:npm/foo@1.0.0".into()),
            reason: Some("audited".into()),
            expires: None,
            vex_status: Some("not_affected".into()),
            vex_justification: Some("vulnerable_code_not_present".into()),
        }];
        let opts = EmitOptions {
            author: "test-suite",
            default_justification: "vulnerable_code_not_in_execute_path",
            baseline_entries: &entries,
        };
        let body = emit(&cs, &e, &opts);

        let dir = std::env::temp_dir().join(format!(
            "bomdrift-vex-emit-rt-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("out.openvex.json");
        std::fs::write(&path, &body).unwrap();
        let stmts = load(&[path]).unwrap();
        assert_eq!(stmts.len(), 1);
        assert_eq!(stmts[0].vuln_id, "GHSA-x-y-z");
        assert_eq!(stmts[0].status, VexStatus::NotAffected);
        assert_eq!(stmts[0].products, vec!["pkg:npm/foo@1.0.0".to_string()]);
        unpin_clock();
    }

    #[test]
    fn emission_default_status_is_under_investigation() {
        // Anti-false-claim guard: a plain baseline entry without
        // `vex_status` must NOT be auto-promoted to `not_affected`.
        let _lock = pin_clock(1_700_000_000);
        let cs = crate::diff::ChangeSet::default();
        let e = crate::enrich::Enrichment::default();
        let entries = vec![crate::baseline::BaselineEntry {
            id: "GHSA-no-status".into(),
            purl: Some("pkg:npm/bar@1.0.0".into()),
            reason: None,
            expires: None,
            vex_status: None,
            vex_justification: None,
        }];
        let opts = EmitOptions {
            author: "x",
            default_justification: "vulnerable_code_not_in_execute_path",
            baseline_entries: &entries,
        };
        let body = emit(&cs, &e, &opts);
        assert!(
            body.contains("\"status\": \"under_investigation\""),
            "default status must be under_investigation, got body:\n{body}"
        );
        assert!(
            !body.contains("\"status\": \"not_affected\""),
            "must not auto-promote to not_affected; got:\n{body}"
        );
        unpin_clock();
    }

    #[test]
    fn emission_byte_deterministic_with_source_date_epoch() {
        let _lock = pin_clock(1_700_000_000);
        let cs = crate::diff::ChangeSet::default();
        let e = crate::enrich::Enrichment::default();
        let entries = vec![crate::baseline::BaselineEntry {
            id: "GHSA-1".into(),
            purl: Some("pkg:npm/foo@1.0.0".into()),
            reason: None,
            expires: None,
            vex_status: Some("not_affected".into()),
            vex_justification: None,
        }];
        let opts = EmitOptions {
            author: "x",
            default_justification: "vulnerable_code_not_in_execute_path",
            baseline_entries: &entries,
        };
        let a = emit(&cs, &e, &opts);
        let b = emit(&cs, &e, &opts);
        assert_eq!(a, b);
        unpin_clock();
    }

    // ---------- v0.9.5: parse_synthetic_id ----------

    fn comp_with_purl(purl: &str) -> crate::model::Component {
        crate::model::Component {
            name: "x".into(),
            version: "1.0.0".into(),
            ecosystem: crate::model::Ecosystem::Npm,
            purl: Some(purl.into()),
            licenses: Vec::new(),
            supplier: None,
            hashes: Vec::new(),
            relationship: crate::model::Relationship::Unknown,
            source_url: None,
            bom_ref: None,
        }
    }

    #[test]
    fn parse_typosquat_round_trip() {
        let f = crate::enrich::typosquat::TyposquatFinding {
            component: comp_with_purl("pkg:npm/plain-crypto-js@4.2.1"),
            closest: "crypto-js".into(),
            score: 0.95,
        };
        let id = synthetic_id::typosquat(&f);
        assert_eq!(
            parse_synthetic_id(&id),
            Some(SyntheticFindingKind::Typosquat {
                purl: "pkg:npm/plain-crypto-js@4.2.1".into(),
                closest: "crypto-js".into(),
            })
        );
    }

    #[test]
    fn parse_version_jump_round_trip() {
        let f = crate::enrich::version_jump::VersionJumpFinding {
            before: comp_with_purl("pkg:npm/lib@1.0.0"),
            after: comp_with_purl("pkg:npm/lib@4.0.0"),
            before_major: 1,
            after_major: 4,
        };
        let id = synthetic_id::version_jump(&f);
        assert_eq!(
            parse_synthetic_id(&id),
            Some(SyntheticFindingKind::VersionJump {
                purl: "pkg:npm/lib@4.0.0".into(),
                before: "1".into(),
                after: "4".into(),
            })
        );
    }

    #[test]
    fn parse_maintainer_age_round_trip() {
        let f = crate::enrich::maintainer::MaintainerAgeFinding {
            component: comp_with_purl("pkg:npm/foo@1.0.0"),
            top_contributor: "alice".into(),
            days_old: 5,
            first_commit_at: "2026-04-26".into(),
        };
        let id = synthetic_id::maintainer_age(&f);
        assert_eq!(
            parse_synthetic_id(&id),
            Some(SyntheticFindingKind::MaintainerAge {
                purl: "pkg:npm/foo@1.0.0".into(),
                top_contributor: "alice".into(),
            })
        );
    }

    #[test]
    fn parse_license_violation_round_trip_with_spdx_with_clause() {
        let v = crate::enrich::LicenseViolation {
            component: comp_with_purl("pkg:cargo/llvm-sys@1.0.0"),
            license: "Apache-2.0 WITH LLVM-exception".into(),
            matched_rule: "deny: GPL-3.0-only".into(),
            kind: crate::enrich::LicenseViolationKind::Deny,
        };
        let id = synthetic_id::license_violation(&v);
        assert_eq!(
            parse_synthetic_id(&id),
            Some(SyntheticFindingKind::LicenseViolation {
                purl: "pkg:cargo/llvm-sys@1.0.0".into(),
                license: "Apache-2.0 WITH LLVM-exception".into(),
            })
        );
    }

    #[test]
    fn parse_license_change_round_trip() {
        let after = comp_with_purl("pkg:npm/foo@2.0.0");
        let id = synthetic_id::license_change(&after);
        assert_eq!(
            parse_synthetic_id(&id),
            Some(SyntheticFindingKind::LicenseChange {
                purl: "pkg:npm/foo@2.0.0".into(),
            })
        );
    }

    #[test]
    fn parse_recently_published_round_trip() {
        let f = crate::enrich::registry::RecentlyPublished {
            component: comp_with_purl("pkg:npm/fresh@0.1.0"),
            published_at: "2026-04-30".into(),
            days_old: 1,
        };
        let id = synthetic_id::recently_published(&f);
        assert_eq!(
            parse_synthetic_id(&id),
            Some(SyntheticFindingKind::RecentlyPublished {
                purl: "pkg:npm/fresh@0.1.0".into(),
            })
        );
    }

    #[test]
    fn parse_deprecated_round_trip() {
        let f = crate::enrich::registry::Deprecated {
            component: comp_with_purl("pkg:npm/old@1.0.0"),
            message: Some("use new-pkg".into()),
        };
        let id = synthetic_id::deprecated(&f);
        assert_eq!(
            parse_synthetic_id(&id),
            Some(SyntheticFindingKind::Deprecated {
                purl: "pkg:npm/old@1.0.0".into(),
            })
        );
    }

    #[test]
    fn parse_maintainer_set_changed_round_trip() {
        let f = crate::enrich::registry::MaintainerSetChanged {
            before: comp_with_purl("pkg:npm/foo@1.0.0"),
            after: comp_with_purl("pkg:npm/foo@2.0.0"),
            added: vec!["mallory".into()],
            removed: vec!["alice".into()],
        };
        let id = synthetic_id::maintainer_set_changed(&f);
        assert_eq!(
            parse_synthetic_id(&id),
            Some(SyntheticFindingKind::MaintainerSetChanged {
                purl: "pkg:npm/foo@2.0.0".into(),
            })
        );
    }

    #[test]
    fn parse_synthetic_id_handles_bare_name_fallback() {
        // When component lacks a purl, the emitter falls back to the
        // bare component name. Round-trip must still work.
        let mut comp = comp_with_purl("");
        comp.purl = None;
        comp.name = "anon-pkg".into();
        let f = crate::enrich::typosquat::TyposquatFinding {
            component: comp,
            closest: "real-pkg".into(),
            score: 0.9,
        };
        let id = synthetic_id::typosquat(&f);
        assert_eq!(id, "bomdrift.typosquat:anon-pkg:real-pkg");
        assert_eq!(
            parse_synthetic_id(&id),
            Some(SyntheticFindingKind::Typosquat {
                purl: "anon-pkg".into(),
                closest: "real-pkg".into(),
            })
        );
    }

    #[test]
    fn parse_synthetic_id_rejects_real_advisory_ids() {
        assert_eq!(parse_synthetic_id("CVE-2024-1234"), None);
        assert_eq!(parse_synthetic_id("GHSA-aaaa-bbbb-cccc"), None);
        assert_eq!(parse_synthetic_id("OSV-2024-9999"), None);
    }

    #[test]
    fn parse_synthetic_id_rejects_malformed_strings() {
        // Missing kind separator.
        assert_eq!(parse_synthetic_id("bomdrift."), None);
        // Unknown kind tag.
        assert_eq!(
            parse_synthetic_id("bomdrift.unknown-kind:pkg:npm/x@1.0.0"),
            None
        );
        // version-jump without `->` separator.
        assert_eq!(
            parse_synthetic_id("bomdrift.version-jump:pkg:npm/x@1.0.0:1to4"),
            None
        );
        // typosquat missing the closest segment.
        assert_eq!(
            parse_synthetic_id("bomdrift.typosquat:pkg:npm/x@1.0.0"),
            None
        );
        // license-change must NOT carry extras.
        assert_eq!(
            parse_synthetic_id("bomdrift.license-change:pkg:npm/x@1.0.0:extra"),
            None
        );
    }
}
