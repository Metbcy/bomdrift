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

mod apply;
mod comment;
mod mutate;

#[cfg(test)]
mod tests;

use std::collections::HashSet;
use std::path::Path;

use anyhow::{Context, Result};

use crate::clock;

pub use apply::apply;
pub use comment::parse_comment_directive;
pub use mutate::{AddOutcome, add_suppression, add_suppression_full};

/// Parsed baseline content: precomputed match-key sets ready for O(1) lookup
/// during suppression. Built once per `bomdrift diff --baseline …` invocation.
#[derive(Debug, Default)]
pub struct Baseline {
    vuln_keys: HashSet<(String, String)>,
    typosquat_keys: HashSet<(String, String)>,
    version_jump_keys: HashSet<(String, u32, u32)>,
    young_maintainer_keys: HashSet<(String, String)>,
    /// v0.5+ wildcard advisory suppression: any advisory ID in this set is
    /// dropped from `e.vulns` regardless of which purl it's attached to.
    /// Populated by `bomdrift baseline add <ADVISORY_ID>` (the
    /// comment-driven suppression flow). The exact-match `vuln_keys` set
    /// remains the canonical match for diff-output-style baselines.
    suppressed_advisories: HashSet<String>,
    /// v0.8+ entries that have already passed their `expires` date.
    /// Surface to the caller for stderr warnings; do NOT contribute to
    /// suppression. Each entry has `expires.is_some()` and is guaranteed
    /// to be strictly before today at load time.
    pub expired_entries: Vec<BaselineEntry>,
    /// v0.9+ rich entries from object-form `suppressed_advisories`.
    /// Keyed in insertion order so VEX emission (Phase H) can surface
    /// `vex_status` / `vex_justification` / `reason` without re-parsing
    /// the source JSON. Both expired and active entries appear here —
    /// callers filter as needed.
    pub entries: Vec<BaselineEntry>,
}

/// A rich baseline entry preserved for VEX emission. Plain string-form
/// entries (`"GHSA-..."`) do NOT appear here — they have no metadata
/// to preserve. Object-form entries always do.
///
/// v0.9.5: previously two distinct structs (`BaselineEntry` and
/// `ExpiredEntry`) overlapped on `id` / `purl` / `expires` / `reason`.
/// They are now a single shape; entries pushed into
/// [`Baseline::expired_entries`] additionally guarantee
/// `expires.is_some()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaselineEntry {
    pub id: String,
    pub purl: Option<String>,
    pub reason: Option<String>,
    pub expires: Option<String>,
    pub vex_status: Option<String>,
    pub vex_justification: Option<String>,
}

/// Back-compat alias for the unified [`BaselineEntry`] shape. Pre-v0.9.5
/// callers used a distinct `ExpiredEntry` struct; the alias preserves
/// `bomdrift::baseline::ExpiredEntry` as a name while sharing the
/// underlying type.
#[deprecated(
    since = "0.9.5",
    note = "use BaselineEntry directly; expired_entries is Vec<BaselineEntry> with expires.is_some()"
)]
pub type ExpiredEntry = BaselineEntry;

impl Baseline {
    pub fn load(path: &Path) -> Result<Self> {
        let body = std::fs::read_to_string(path)
            .with_context(|| format!("reading baseline file: {}", path.display()))?;
        let value: serde_json::Value = serde_json::from_str(&body)
            .with_context(|| format!("parsing baseline JSON: {}", path.display()))?;
        Self::from_value_strict(&value)
    }

    /// Build a `Baseline` from an already-parsed bomdrift JSON document.
    /// Tolerant: a missing `enrichment` or `changes` block produces an
    /// empty key set for that section, never an error. Malformed
    /// `expires` dates are silently ignored — use [`Self::from_value_strict`]
    /// if you want to surface those as errors.
    pub fn from_value(value: &serde_json::Value) -> Self {
        Self::from_value_inner(value, false).unwrap_or_default()
    }

    /// Strict variant: an object-form `suppressed_advisories` entry with a
    /// malformed `expires` date is an error rather than a silent skip.
    /// Used by [`Self::load`] so users see typos immediately.
    pub fn from_value_strict(value: &serde_json::Value) -> Result<Self> {
        Self::from_value_inner(value, true)
    }

    fn from_value_inner(value: &serde_json::Value, strict: bool) -> Result<Self> {
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

        // v0.5+ simple suppression list, optionally extended in v0.8 to
        // object form `{ "id": ..., "purl": ..., "expires": ..., "reason": ... }`.
        // Both shapes coexist in one array. Keys read: `suppressed_advisories`
        // (canonical) and `suppressed_ids` (alias retained for back-compat).
        for key in ["suppressed_advisories", "suppressed_ids"] {
            if let Some(arr) = value[key].as_array() {
                for entry in arr {
                    // String form (v0.5+).
                    if let Some(id) = entry.as_str() {
                        if !id.is_empty() {
                            out.suppressed_advisories.insert(id.to_string());
                        }
                        continue;
                    }
                    // Object form (v0.8+).
                    if let Some(obj) = entry.as_object() {
                        let id = obj.get("id").and_then(|v| v.as_str()).unwrap_or("");
                        if id.is_empty() {
                            if strict {
                                anyhow::bail!(
                                    "baseline `{key}` entry missing required `id` field: {entry}"
                                );
                            }
                            continue;
                        }
                        let purl = obj.get("purl").and_then(|v| v.as_str()).map(str::to_string);
                        let reason = obj
                            .get("reason")
                            .and_then(|v| v.as_str())
                            .map(str::to_string);
                        let vex_status = obj
                            .get("vex_status")
                            .and_then(|v| v.as_str())
                            .map(str::to_string);
                        let vex_justification = obj
                            .get("vex_justification")
                            .and_then(|v| v.as_str())
                            .map(str::to_string);
                        let expires_str = obj
                            .get("expires")
                            .and_then(|v| v.as_str())
                            .map(str::to_string);
                        // Track the rich entry for VEX emission regardless
                        // of expiry — emission may include expired entries
                        // for documentation; suppression below honors expiry.
                        out.entries.push(BaselineEntry {
                            id: id.to_string(),
                            purl: purl.clone(),
                            reason: reason.clone(),
                            expires: expires_str.clone(),
                            vex_status: vex_status.clone(),
                            vex_justification: vex_justification.clone(),
                        });
                        if let Some(expires_s) = expires_str.as_deref() {
                            match clock::parse_ymd(expires_s) {
                                Ok(date) => {
                                    if clock::is_expired(date) {
                                        out.expired_entries.push(BaselineEntry {
                                            id: id.to_string(),
                                            purl: purl.clone(),
                                            reason: reason.clone(),
                                            expires: expires_str.clone(),
                                            vex_status: vex_status.clone(),
                                            vex_justification: vex_justification.clone(),
                                        });
                                        // Expired entries do NOT contribute to suppression.
                                        continue;
                                    }
                                }
                                Err(err) => {
                                    if strict {
                                        return Err(err.context(format!(
                                            "baseline entry {id} ({}): malformed expires",
                                            purl.as_deref().unwrap_or("*")
                                        )));
                                    }
                                    continue;
                                }
                            }
                        }
                        out.suppressed_advisories.insert(id.to_string());
                    }
                }
            }
        }

        Ok(out)
    }

    /// True when this baseline contains zero suppressible entries (e.g. an
    /// empty file or a baseline with `{"changes": {…}}` only). Lets callers
    /// short-circuit the suppression pass cheaply.
    pub fn is_empty(&self) -> bool {
        self.vuln_keys.is_empty()
            && self.typosquat_keys.is_empty()
            && self.version_jump_keys.is_empty()
            && self.young_maintainer_keys.is_empty()
            && self.suppressed_advisories.is_empty()
    }
}

pub(super) fn doc_kind(v: &serde_json::Value) -> &'static str {
    match v {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "bool",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}
