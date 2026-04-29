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
    /// v0.5+ wildcard advisory suppression: any advisory ID in this set is
    /// dropped from `e.vulns` regardless of which purl it's attached to.
    /// Populated by `bomdrift baseline add <ADVISORY_ID>` (the
    /// comment-driven suppression flow). The exact-match `vuln_keys` set
    /// remains the canonical match for diff-output-style baselines.
    suppressed_advisories: HashSet<String>,
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

        // v0.5+ simple suppression list — written by
        // `bomdrift baseline add <ADVISORY_ID>`. Any advisory ID in this
        // array suppresses across ALL purls. The shape is forgiving:
        // accepts a JSON array of strings under either
        // `suppressed_advisories` (canonical) or `suppressed_ids` (alias
        // we kept short for hand-edited use). Both are read; either form
        // is valid output from `baseline add`.
        for key in ["suppressed_advisories", "suppressed_ids"] {
            if let Some(arr) = value[key].as_array() {
                for entry in arr {
                    if let Some(id) = entry.as_str() {
                        if !id.is_empty() {
                            out.suppressed_advisories.insert(id.to_string());
                        }
                    }
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
    let trimmed = id.trim();
    if trimmed.is_empty() {
        anyhow::bail!("advisory id must not be empty");
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

    let already_present = arr
        .iter()
        .any(|v| v.as_str().map(|s| s == trimmed).unwrap_or(false));
    if already_present {
        return Ok(AddOutcome::AlreadyPresent);
    }
    arr.push(serde_json::Value::String(trimmed.to_string()));

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating parent dir: {}", parent.display()))?;
        }
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
                },
                VulnRef {
                    id: "CVE-2".into(),
                    severity: Severity::Medium,
                    aliases: Vec::new(),
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
                },
                VulnRef {
                    id: "CVE-still-here".into(),
                    severity: Severity::Medium,
                    aliases: Vec::new(),
                },
            ],
        );
        e.vulns.insert(
            "pkg:npm/bar@2.0".into(),
            vec![VulnRef {
                id: "GHSA-evil-1234".into(),
                severity: Severity::Critical,
                aliases: Vec::new(),
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
}
