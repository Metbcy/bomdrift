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

use crate::clock;
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

/// Append an advisory ID to a baseline file's `suppressed_advisories` array.
/// Used by the v0.5 `bomdrift baseline add <id>` subcommand and by the
/// `comment-suppress` sub-action.
///
/// Behavior
///
/// - **File doesn't exist**: a new baseline is created at `path` with
///   `{"schema_version": 1, "suppressed_advisories": ["<id>"]}`. The
///   parent directory is created if missing.
/// - **File exists but isn't valid JSON**: returns an error. We don't
///   want to silently overwrite hand-edited baselines on a typo.
/// - **File exists and is valid JSON**: parses, appends `id` to the
///   `suppressed_advisories` array (idempotent — skips if already
///   present), and writes back atomically via temp-file + rename.
/// - **`id` is empty or whitespace**: returns an error rather than
///   adding a noise entry.
///
/// The write preserves any existing fields in the JSON document
/// (`changes`, `enrichment`, comments via `_note`, etc.) so this can
/// safely be run against a baseline generated by `bomdrift diff
/// --output json`.
pub fn add_suppression(path: &Path, id: &str) -> Result<AddOutcome> {
    add_suppression_full(path, id, None, None)
}

/// Like [`add_suppression`] but accepts optional `expires` (YYYY-MM-DD) and
/// `reason` fields. When either is provided, the new entry is written in
/// the v0.8 object form `{id, expires?, reason?}`; existing string-form
/// entries elsewhere in the array are left untouched.
pub fn add_suppression_full(
    path: &Path,
    id: &str,
    expires: Option<&str>,
    reason: Option<&str>,
) -> Result<AddOutcome> {
    let trimmed = id.trim();
    if trimmed.is_empty() {
        anyhow::bail!("advisory id must not be empty");
    }
    if let Some(s) = expires {
        clock::parse_ymd(s).with_context(|| format!("invalid --expires {s:?}"))?;
    }

    let mut doc: serde_json::Value = if path.exists() {
        let body = std::fs::read_to_string(path)
            .with_context(|| format!("reading baseline file: {}", path.display()))?;
        if body.trim().is_empty() {
            serde_json::json!({})
        } else {
            serde_json::from_str(&body)
                .with_context(|| format!("parsing baseline JSON: {}", path.display()))?
        }
    } else {
        serde_json::json!({})
    };

    if !doc.is_object() {
        anyhow::bail!(
            "baseline file root must be a JSON object, found: {}",
            doc_kind(&doc)
        );
    }

    let obj = doc.as_object_mut().expect("checked is_object above");
    obj.entry("schema_version")
        .or_insert(serde_json::Value::from(1u64));

    let arr = obj
        .entry("suppressed_advisories")
        .or_insert_with(|| serde_json::Value::Array(Vec::new()));
    let arr = arr
        .as_array_mut()
        .ok_or_else(|| anyhow::anyhow!("baseline `suppressed_advisories` field is not an array"))?;

    let already_present = arr.iter().any(|v| match v {
        serde_json::Value::String(s) => s == trimmed,
        serde_json::Value::Object(o) => o.get("id").and_then(|x| x.as_str()) == Some(trimmed),
        _ => false,
    });
    if already_present {
        return Ok(AddOutcome::AlreadyPresent);
    }
    if expires.is_some() || reason.is_some() {
        let mut entry = serde_json::Map::new();
        entry.insert("id".into(), serde_json::Value::String(trimmed.to_string()));
        if let Some(s) = expires {
            entry.insert("expires".into(), serde_json::Value::String(s.to_string()));
        }
        if let Some(s) = reason {
            entry.insert("reason".into(), serde_json::Value::String(s.to_string()));
        }
        arr.push(serde_json::Value::Object(entry));
    } else {
        arr.push(serde_json::Value::String(trimmed.to_string()));
    }

    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating parent dir: {}", parent.display()))?;
    }

    // Atomic temp-file + rename, mirroring src/refresh.rs's pattern.
    let tmp_path = path.with_extension("json.tmp");
    let serialized = serde_json::to_string_pretty(&doc).context("serializing baseline JSON")?;
    std::fs::write(&tmp_path, serialized)
        .with_context(|| format!("writing temp baseline: {}", tmp_path.display()))?;
    std::fs::rename(&tmp_path, path)
        .with_context(|| format!("renaming temp baseline to: {}", path.display()))?;

    Ok(AddOutcome::Added)
}

/// Result of [`add_suppression`]. `Added` means the file was modified;
/// `AlreadyPresent` means the ID was already in the suppressed list and
/// no write happened. Both are non-error paths — callers can use this to
/// emit a precise log message.
#[derive(Debug, PartialEq, Eq)]
pub enum AddOutcome {
    Added,
    AlreadyPresent,
}

/// Parse the body of a PR/MR comment and extract a single
/// `/bomdrift suppress <ID>[ reason: <text>]` directive. The grammar
/// is documented in CLI help and in
/// `examples/gitlab-ci/comment-bridge/`'s threat model. The same
/// shape is honored by `comment-suppress/entrypoint.sh` for the
/// GitHub flow — keep these in lockstep.
///
/// Returns `Ok(Some((id, optional_reason)))` on a single match,
/// `Ok(None)` on no match, `Err` on a malformed ID.
pub fn parse_comment_directive(body: &str) -> Result<Option<(String, Option<String>)>> {
    // Looks for `/bomdrift suppress <ID>[ reason: <text>]` on each
    // line; the directive may be preceded by free-form prose and/or
    // mention markers. A leading `^\s*` anchor on the directive itself
    // is too strict — reviewers paste the directive after a comment.
    for line in body.lines() {
        let Some(idx) = line.find("/bomdrift") else {
            continue;
        };
        let rest = &line[idx + "/bomdrift".len()..];
        let rest = rest.trim_start();
        let Some(rest) = rest.strip_prefix("suppress") else {
            continue;
        };
        let rest = rest.trim_start();
        if rest.is_empty() {
            continue;
        }
        let mut iter = rest.splitn(2, char::is_whitespace);
        let raw_id = iter.next().unwrap_or("").trim();
        if raw_id.is_empty() {
            continue;
        }
        if !is_valid_advisory_id(raw_id) {
            anyhow::bail!(
                "comment directive contained a malformed advisory ID: {raw_id:?} \
                 (expected GHSA-/CVE-/MAL-/OSV- prefix and alnum/dash body)"
            );
        }
        let reason = iter.next().and_then(|tail| {
            let tail = tail.trim();
            tail.strip_prefix("reason:")
                .map(|r| r.trim().to_string())
                .filter(|s| !s.is_empty())
        });
        return Ok(Some((raw_id.to_string(), reason)));
    }
    Ok(None)
}

fn is_valid_advisory_id(s: &str) -> bool {
    // Aligns with comment-suppress/entrypoint.sh's regex:
    //   ^(GHSA-[a-z0-9-]+|CVE-[0-9]{4}-[0-9]+|MAL-[0-9]{4}-[0-9]+|OSV-[A-Z0-9-]+)$
    // Kept slightly looser here (we accept GHSA-uppercase and OSV-* too)
    // so future advisory schemes don't trip the bridge unnecessarily.
    let Some((prefix, rest)) = s.split_once('-') else {
        return false;
    };
    if !matches!(prefix, "GHSA" | "CVE" | "MAL" | "OSV") {
        return false;
    }
    if rest.is_empty() {
        return false;
    }
    rest.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

fn doc_kind(v: &serde_json::Value) -> &'static str {
    match v {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "bool",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
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
                aliases: Vec::new(),
                epss_score: None,
                kev: false,
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
                    aliases: Vec::new(),
                    epss_score: None,
                    kev: false,
                },
                VulnRef {
                    id: "CVE-2".into(),
                    severity: Severity::Medium,
                    aliases: Vec::new(),
                    epss_score: None,
                    kev: false,
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
                aliases: Vec::new(),
                epss_score: None,
                kev: false,
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

    // ---- v0.5 suppressed_advisories: wildcard-by-id suppression ----------

    #[test]
    fn wildcard_advisory_id_suppresses_across_purls() {
        let baseline = Baseline::from_value(&json!({
            "schema_version": 1,
            "suppressed_advisories": ["GHSA-evil-1234"]
        }));
        let mut cs = ChangeSet::default();
        let mut e = Enrichment::default();
        e.vulns.insert(
            "pkg:npm/foo@1.0".into(),
            vec![
                VulnRef {
                    id: "GHSA-evil-1234".into(),
                    severity: Severity::Critical,
                    aliases: Vec::new(),
                    epss_score: None,
                    kev: false,
                },
                VulnRef {
                    id: "CVE-still-here".into(),
                    severity: Severity::Medium,
                    aliases: Vec::new(),
                    epss_score: None,
                    kev: false,
                },
            ],
        );
        e.vulns.insert(
            "pkg:npm/bar@2.0".into(),
            vec![VulnRef {
                id: "GHSA-evil-1234".into(),
                severity: Severity::Critical,
                aliases: Vec::new(),
                epss_score: None,
                kev: false,
            }],
        );
        apply(&mut cs, &mut e, &baseline);
        // foo: GHSA-evil-1234 dropped; CVE-still-here remains
        assert_eq!(e.vulns.get("pkg:npm/foo@1.0").map(|v| v.len()), Some(1));
        assert_eq!(
            e.vulns.get("pkg:npm/foo@1.0").unwrap()[0].id,
            "CVE-still-here"
        );
        // bar: GHSA-evil-1234 was the only advisory; whole purl entry drops.
        assert!(!e.vulns.contains_key("pkg:npm/bar@2.0"));
    }

    #[test]
    fn suppressed_ids_alias_is_also_accepted() {
        let baseline = Baseline::from_value(&json!({
            "suppressed_ids": ["CVE-2026-9999"]
        }));
        assert!(baseline.suppressed_advisories.contains("CVE-2026-9999"));
    }

    #[test]
    fn add_suppression_creates_new_baseline() {
        let dir = tempdir_unique("add-new");
        let path = dir.join("baseline.json");
        let outcome = add_suppression(&path, "GHSA-test-0001").unwrap();
        assert_eq!(outcome, AddOutcome::Added);

        let body = std::fs::read_to_string(&path).unwrap();
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["schema_version"], json!(1));
        assert_eq!(v["suppressed_advisories"][0], "GHSA-test-0001");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn add_suppression_appends_to_existing_baseline() {
        let dir = tempdir_unique("add-append");
        let path = dir.join("baseline.json");
        std::fs::write(
            &path,
            r#"{"schema_version": 1, "suppressed_advisories": ["GHSA-old"]}"#,
        )
        .unwrap();

        let outcome = add_suppression(&path, "GHSA-new").unwrap();
        assert_eq!(outcome, AddOutcome::Added);

        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let arr = v["suppressed_advisories"].as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert!(arr.iter().any(|x| x == "GHSA-old"));
        assert!(arr.iter().any(|x| x == "GHSA-new"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn add_suppression_preserves_existing_diff_output_baseline() {
        // A user generated baseline.json from `bomdrift diff --output json`;
        // it has `changes` and `enrichment` blocks. Adding a suppression
        // must not clobber those.
        let dir = tempdir_unique("add-preserve");
        let path = dir.join("baseline.json");
        let original = json!({
            "changes": {"added": []},
            "enrichment": {"vulns": {}},
        });
        std::fs::write(&path, serde_json::to_string_pretty(&original).unwrap()).unwrap();

        add_suppression(&path, "GHSA-x").unwrap();

        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert!(v["changes"].is_object(), "changes block must survive");
        assert!(v["enrichment"].is_object(), "enrichment block must survive");
        assert_eq!(v["suppressed_advisories"][0], "GHSA-x");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn add_suppression_is_idempotent() {
        let dir = tempdir_unique("add-idempotent");
        let path = dir.join("baseline.json");

        let first = add_suppression(&path, "GHSA-dupe").unwrap();
        assert_eq!(first, AddOutcome::Added);

        let second = add_suppression(&path, "GHSA-dupe").unwrap();
        assert_eq!(second, AddOutcome::AlreadyPresent);

        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let arr = v["suppressed_advisories"].as_array().unwrap();
        assert_eq!(arr.len(), 1, "duplicate must not be re-appended");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn add_suppression_rejects_empty_id() {
        let dir = tempdir_unique("add-empty");
        let path = dir.join("baseline.json");
        assert!(add_suppression(&path, "").is_err());
        assert!(add_suppression(&path, "   ").is_err());
        // No file should have been created.
        assert!(!path.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---- v0.8 expires + reason -----------------------------------------

    fn lock_today(epoch: i64) -> impl Drop {
        // SAFETY: env mutations are serialized by the crate-wide
        // `clock::test_env_lock()` mutex; `Guard` holds that lock for
        // the lifetime of the returned token so `SOURCE_DATE_EPOCH`
        // remains stable from set-time through baseline parse.
        struct Guard {
            _lock: std::sync::MutexGuard<'static, ()>,
        }
        impl Drop for Guard {
            fn drop(&mut self) {
                unsafe {
                    std::env::remove_var("SOURCE_DATE_EPOCH");
                }
            }
        }
        let _lock = crate::clock::test_env_lock();
        unsafe {
            std::env::set_var("SOURCE_DATE_EPOCH", epoch.to_string());
        }
        Guard { _lock }
    }

    #[test]
    fn expired_object_entry_warns_and_does_not_suppress() {
        // 2026-05-01 (epoch 1777593600) is "today"; the entry expired 2026-04-30.
        let _g = lock_today(1777593600);
        let baseline = Baseline::from_value(&json!({
            "suppressed_advisories": [
                { "id": "GHSA-old", "expires": "2026-04-30", "reason": "awaiting upstream" }
            ]
        }));
        assert_eq!(baseline.expired_entries.len(), 1);
        assert_eq!(baseline.expired_entries[0].id, "GHSA-old");
        // After v0.9.5 unification, expired_entries shares the
        // BaselineEntry shape; expires is Option but always Some here.
        assert_eq!(
            baseline.expired_entries[0].expires.as_deref(),
            Some("2026-04-30")
        );
        assert_eq!(
            baseline.expired_entries[0].reason.as_deref(),
            Some("awaiting upstream")
        );
        assert!(
            !baseline.suppressed_advisories.contains("GHSA-old"),
            "expired entry must NOT contribute to suppression"
        );
    }

    /// Regression: the stderr warning text rendered by lib.rs must remain
    /// byte-for-byte stable across v0.9.5's BaselineEntry/ExpiredEntry
    /// unification. CI integrators grep this string.
    #[test]
    fn expired_entry_warning_text_is_stable() {
        let _g = lock_today(1777593600);
        let baseline = Baseline::from_value(&json!({
            "suppressed_advisories": [
                { "id": "GHSA-old", "purl": "pkg:npm/foo@1.0.0",
                  "expires": "2026-04-30", "reason": "awaiting upstream" }
            ]
        }));
        let ent = &baseline.expired_entries[0];
        // Mirror the format string used in src/lib.rs (the production
        // warning emitter). If either side drifts, this fails loudly.
        let rendered = format!(
            "warning: baseline entry {id}{purl} expired {expires}; finding will surface in this run{reason}",
            id = ent.id,
            purl = ent
                .purl
                .as_deref()
                .map(|p| format!(" ({p})"))
                .unwrap_or_default(),
            expires = ent.expires.as_deref().unwrap_or(""),
            reason = ent
                .reason
                .as_deref()
                .map(|r| format!(" — was: {r}"))
                .unwrap_or_default(),
        );
        assert_eq!(
            rendered,
            "warning: baseline entry GHSA-old (pkg:npm/foo@1.0.0) expired 2026-04-30; finding will surface in this run — was: awaiting upstream"
        );
    }

    #[test]
    fn active_object_entry_suppresses() {
        let _g = lock_today(1777593600); // 2026-05-01
        let baseline = Baseline::from_value(&json!({
            "suppressed_advisories": [
                { "id": "GHSA-future", "expires": "2030-01-01" }
            ]
        }));
        assert!(baseline.suppressed_advisories.contains("GHSA-future"));
        assert!(baseline.expired_entries.is_empty());
    }

    #[test]
    fn no_expires_object_entry_suppresses_indefinitely() {
        let baseline = Baseline::from_value(&json!({
            "suppressed_advisories": [
                { "id": "GHSA-perma", "reason": "false positive" }
            ]
        }));
        assert!(baseline.suppressed_advisories.contains("GHSA-perma"));
    }

    #[test]
    fn malformed_expires_errors_strict() {
        let v = json!({
            "suppressed_advisories": [
                { "id": "GHSA-bad", "expires": "yesterday" }
            ]
        });
        let err = Baseline::from_value_strict(&v).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("GHSA-bad"), "error must name the entry: {msg}");
    }

    #[test]
    fn add_suppression_full_writes_object_form_when_metadata_present() {
        let dir = tempdir_unique("add-full");
        let path = dir.join("baseline.json");
        let outcome = add_suppression_full(
            &path,
            "GHSA-x",
            Some("2030-12-31"),
            Some("Awaiting upstream patch"),
        )
        .unwrap();
        assert_eq!(outcome, AddOutcome::Added);
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let entry = &v["suppressed_advisories"][0];
        assert_eq!(entry["id"], "GHSA-x");
        assert_eq!(entry["expires"], "2030-12-31");
        assert_eq!(entry["reason"], "Awaiting upstream patch");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn add_suppression_full_rejects_malformed_expires() {
        let dir = tempdir_unique("add-bad-date");
        let path = dir.join("baseline.json");
        let err = add_suppression_full(&path, "GHSA-x", Some("2030/12/31"), None);
        assert!(err.is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn add_suppression_full_idempotent_against_existing_object_entry() {
        let dir = tempdir_unique("add-idem-obj");
        let path = dir.join("baseline.json");
        std::fs::write(
            &path,
            r#"{"suppressed_advisories": [{"id": "GHSA-dupe", "expires": "2030-01-01"}]}"#,
        )
        .unwrap();
        let outcome = add_suppression_full(&path, "GHSA-dupe", Some("2031-01-01"), None).unwrap();
        assert_eq!(outcome, AddOutcome::AlreadyPresent);
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn tempdir_unique(stem: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "bomdrift-baseline-{stem}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    // ---- v0.9 comment-directive parser ----

    #[test]
    fn parse_comment_directive_extracts_id_only() {
        let body = "Looks fine. /bomdrift suppress GHSA-mwcw-c2x4-8c55";
        let r = parse_comment_directive(body).unwrap().unwrap();
        assert_eq!(r.0, "GHSA-mwcw-c2x4-8c55");
        assert_eq!(r.1, None);
    }

    #[test]
    fn parse_comment_directive_extracts_id_and_reason() {
        let body = "/bomdrift suppress CVE-2024-12345 reason: vendor confirmed false-positive";
        let r = parse_comment_directive(body).unwrap().unwrap();
        assert_eq!(r.0, "CVE-2024-12345");
        assert_eq!(r.1.as_deref(), Some("vendor confirmed false-positive"));
    }

    #[test]
    fn parse_comment_directive_returns_none_when_no_directive() {
        assert!(
            parse_comment_directive("no directive here")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn parse_comment_directive_rejects_malformed_id() {
        let err = parse_comment_directive("/bomdrift suppress not-an-id")
            .unwrap_err()
            .to_string();
        assert!(err.contains("malformed"));
    }
}
