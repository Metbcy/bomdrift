//! SARIF v2.1.0 renderer (`--output sarif`).
//!
//! Produces a single-run SARIF document suitable for ingestion by GitHub Code
//! Scanning, GitLab Vulnerability Reports, and any other consumer that speaks
//! SARIF. The schema is hand-built via `serde_json::json!` — pulling a `sarif`
//! crate would add ~30 transitive dependencies for what amounts to ~50 lines
//! of object construction.
//!
//! ## Stable rule IDs (NEVER rename)
//!
//! These IDs surface in GitHub Code Scanning's UI and are the join key for
//! suppressions, so they're load-bearing public API once a finding has been
//! seen by any consumer:
//!
//! - `bomdrift.cve` — one result per `(component, advisory_id)` from
//!   `enrichment.vulns`.
//! - `bomdrift.typosquat` — one per `enrichment.typosquats` finding.
//! - `bomdrift.version-jump` — one per `enrichment.version_jumps` finding.
//! - `bomdrift.young-maintainer` — one per `enrichment.maintainer_age` finding.
//! - `bomdrift.license-change` — one per `cs.license_changed` pair (license
//!   changed without a version bump — the suspicious case).
//!
//! All five rules are always emitted in `tool.driver.rules`, even when the
//! current diff has zero findings of that kind. Code Scanning consumers
//! enumerate the rules independently of the results, so omitting unused
//! rules confuses suppression UIs.
//!
//! ## Severity
//!
//! `bomdrift.cve` results map their per-advisory severity to SARIF `level`:
//! `Critical` and `High` → `"error"`, everything else (including `None`,
//! used when /v1/vulns/{id} couldn't resolve a label) → `"warning"`. The
//! heuristic-enricher rules (typosquat, version-jump, maintainer-age,
//! license-change) stay at `"warning"` — they're intentionally informational.
//!
//! ## Locations
//!
//! SARIF requires `locations` on every `result`. We emit a synthetic
//! `physicalLocation.artifactLocation.uri = "sbom"`, matching the convention
//! used by `trivy` for SBOM-derived findings (no source line numbers exist —
//! the SBOM itself is the artifact).
//!
//! ## Determinism
//!
//! Renderer determinism is the upsert contract for PR comment workflows.
//! `Enrichment::vulns` is a `HashMap` (iteration order non-deterministic), so
//! its entries are sorted by purl key before emission. The other finding
//! collections are already `Vec`s ordered by their enrichers (which iterate
//! the `ChangeSet`'s BTreeMap-derived order), so they need no extra sorting.
//! The render-twice-byte-equal regression test below guards this.

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::diff::ChangeSet;
use crate::enrich::Enrichment;

/// SARIF schema URL pinned to v2.1.0. GitHub Code Scanning accepts both
/// `master` and `2.1.0` paths; pin to the version-tagged one for stability.
const SARIF_SCHEMA: &str = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json";
const SARIF_VERSION: &str = "2.1.0";

/// Synthetic artifact URI for all results. SARIF requires a `physicalLocation`
/// on every `result`; an SBOM-derived finding has no source line, so we
/// project all results onto a single virtual `sbom` artifact.
const SARIF_ARTIFACT_URI: &str = "sbom";

pub fn render(cs: &ChangeSet, e: &Enrichment) -> String {
    let doc = json!({
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {
                "driver": {
                    "name": "bomdrift",
                    "semanticVersion": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://metbcy.github.io/bomdrift/",
                    "rules": rules(),
                }
            },
            "results": results(cs, e),
        }]
    });
    serde_json::to_string_pretty(&doc).expect("serialize SARIF")
}

fn rules() -> Value {
    json!([
        rule(
            "bomdrift.cve",
            "cve",
            "Known CVE / advisory affects this component",
            "OSV.dev returned one or more advisory IDs (CVE, GHSA, MAL, etc.) \
             for the component at this version. Per-advisory severity is \
             populated via /v1/vulns/{id} (GHSA `database_specific.severity`); \
             results map Critical/High to SARIF `error`, lower buckets to \
             `warning`. Advisories with no resolvable severity surface as \
             `warning` and don't trip `--fail-on critical-cve`.",
            "https://metbcy.github.io/bomdrift/enrichers/osv-cve.html",
        ),
        rule(
            "bomdrift.typosquat",
            "typosquat",
            "Newly added component name is similar to a popular package",
            "The added component's name is suspiciously close to a popular \
             package in the same ecosystem. High similarity does not prove \
             malicious intent — investigate the package source before merging. \
             Always informational severity (`warning`).",
            "https://metbcy.github.io/bomdrift/enrichers/typosquat.html",
        ),
        rule(
            "bomdrift.version-jump",
            "version-jump",
            "Multi-major version bump detected",
            "The component's major version increased by 2 or more in a single \
             diff (e.g. 1.x to 4.x). Multi-major bumps correlate with \
             takeover swaps and namespace reuse, not just legitimate \
             refactors. Always informational severity (`warning`).",
            "https://metbcy.github.io/bomdrift/enrichers/version-jump.html",
        ),
        rule(
            "bomdrift.young-maintainer",
            "young-maintainer",
            "Top contributor's first commit is recent",
            "The newly added component is hosted on GitHub and its top \
             contributor's first commit is younger than 90 days. The xz / \
             Jia Tan supply-chain-takeover pattern. Always informational \
             severity (`warning`).",
            "https://metbcy.github.io/bomdrift/enrichers/maintainer-age.html",
        ),
        rule(
            "bomdrift.license-change",
            "license-change",
            "License changed without a version bump",
            "The component's license set differs between before and after at \
             the SAME version. Could indicate a corrected SBOM, a \
             license-rug-pull, or a supply-chain swap. Worth a human glance \
             regardless. Always informational severity (`warning`).",
            "https://metbcy.github.io/bomdrift/output-formats.html#sarif-v210",
        ),
        rule(
            "bomdrift.license-violation",
            "license-violation",
            "Component license violates configured allow/deny policy",
            "The component's declared license is on the deny list, doesn't \
             appear on the allow list, or is a compound expression that \
             cannot be safely evaluated against the configured policy (with \
             `allow_ambiguous=false`). Configure via the `[license]` block \
             in `.bomdrift.toml` or the `--allow-licenses` / `--deny-licenses` \
             CLI flags. Severity `error` (this is a policy gate, not an \
             advisory heuristic).",
            "https://metbcy.github.io/bomdrift/license-policy.html",
        ),
    ])
}

/// Stable per-rule identity hash for SARIF `partialFingerprints`. GitHub
/// Code Scanning uses these to thread alert state across runs (resolved /
/// dismissed / open) so the value MUST stay byte-equal for the same logical
/// finding. We hex-encode SHA-256 of a `|`-joined identity string so the
/// inputs are inspectable from a debugger and the output is filename-safe.
///
/// The `/v1` suffix on the fingerprint key (see emit sites) lets us evolve
/// the identity scheme later without GitHub re-opening every alert.
pub(crate) fn fingerprint(parts: &[&str]) -> String {
    let mut h = Sha256::new();
    for (i, p) in parts.iter().enumerate() {
        if i > 0 {
            h.update(b"|");
        }
        h.update(p.as_bytes());
    }
    let digest = h.finalize();
    let mut out = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn rule(id: &str, name: &str, short: &str, full: &str, help_uri: &str) -> Value {
    json!({
        "id": id,
        "name": name,
        "shortDescription": { "text": short },
        "fullDescription":  { "text": full },
        "helpUri": help_uri,
        "defaultConfiguration": { "level": "warning" },
    })
}

fn results(cs: &ChangeSet, e: &Enrichment) -> Value {
    let mut out: Vec<Value> = Vec::new();

    // ---- bomdrift.cve ----
    // Sort vulns by purl key for deterministic output (HashMap iteration is
    // non-deterministic). Inner advisory list is sorted highest-severity
    // first then by id, matching the markdown / term renderers so a SARIF
    // reader and a PR-comment reader see the same priority order.
    let mut vuln_keys: Vec<&String> = e.vulns.keys().collect();
    vuln_keys.sort();
    for purl in vuln_keys {
        let mut advisories: Vec<&crate::enrich::VulnRef> = e.vulns[purl].iter().collect();
        advisories.sort_by(|a, b| b.severity.cmp(&a.severity).then_with(|| a.id.cmp(&b.id)));
        for advisory in advisories {
            let purl_str: &str = purl;
            let fp = fingerprint(&["bomdrift.cve", purl_str, &advisory.id]);
            let mut props = serde_json::Map::new();
            props.insert("purl".into(), Value::String(purl.clone()));
            props.insert("advisoryId".into(), Value::String(advisory.id.clone()));
            props.insert(
                "severity".into(),
                Value::String(advisory.severity.as_str().into()),
            );
            if let Some(score) = advisory.epss_score {
                props.insert(
                    "epssScore".into(),
                    serde_json::Number::from_f64(score as f64)
                        .map(Value::Number)
                        .unwrap_or(Value::Null),
                );
            }
            if advisory.kev {
                props.insert("kev".into(), Value::Bool(true));
            }
            let vex_key = format!("cve:{purl_str}:{}", advisory.id);
            if let Some(ann) = e.vex_annotations.get(&vex_key) {
                props.insert("vexStatus".into(), Value::String(ann.status.clone()));
                if let Some(j) = &ann.justification {
                    props.insert("vexJustification".into(), Value::String(j.clone()));
                }
            }
            out.push(json!({
                "ruleId": "bomdrift.cve",
                "level": sarif_level(advisory.severity),
                "message": {
                    "text": format!(
                        "{} ({}) affects {purl}. Review the advisory and update \
                         or pin a patched version.",
                        advisory.id,
                        advisory.severity,
                    ),
                },
                "locations": [synthetic_location()],
                "partialFingerprints": { "primaryHash/v1": fp },
                "properties": Value::Object(props),
            }));
        }
    }

    // ---- bomdrift.typosquat ----
    for finding in &e.typosquats {
        let name = &finding.component.name;
        let closest = &finding.closest;
        let purl_or_name = finding.component.purl.as_deref().unwrap_or(name);
        let fp = fingerprint(&["bomdrift.typosquat", purl_or_name, closest]);
        out.push(json!({
            "ruleId": "bomdrift.typosquat",
            "level": "warning",
            "message": {
                "text": format!(
                    "`{name}` is similar to popular package `{closest}` (similarity {:.2}). \
                     Verify the package source before merging.",
                    finding.score,
                ),
            },
            "locations": [synthetic_location()],
            "partialFingerprints": { "primaryHash/v1": fp },
            "properties": {
                "purl":       finding.component.purl,
                "name":       name,
                "version":    finding.component.version,
                "closest":    closest,
                "similarity": finding.score,
            },
        }));
    }

    // ---- bomdrift.version-jump ----
    for finding in &e.version_jumps {
        let name = &finding.after.name;
        let purl_or_name = finding.after.purl.as_deref().unwrap_or(name);
        let fp = fingerprint(&[
            "bomdrift.version-jump",
            purl_or_name,
            &finding.before.version,
            &finding.after.version,
        ]);
        out.push(json!({
            "ruleId": "bomdrift.version-jump",
            "level": "warning",
            "message": {
                "text": format!(
                    "`{name}` jumped from {} to {} (major {} -> {}). Multi-major \
                     bumps deserve extra scrutiny.",
                    finding.before.version,
                    finding.after.version,
                    finding.before_major,
                    finding.after_major,
                ),
            },
            "locations": [synthetic_location()],
            "partialFingerprints": { "primaryHash/v1": fp },
            "properties": {
                "purl":         finding.after.purl,
                "name":         name,
                "beforeVersion": finding.before.version,
                "afterVersion":  finding.after.version,
                "beforeMajor":   finding.before_major,
                "afterMajor":    finding.after_major,
            },
        }));
    }

    // ---- bomdrift.young-maintainer ----
    for finding in &e.maintainer_age {
        let name = &finding.component.name;
        let purl_or_name = finding.component.purl.as_deref().unwrap_or(name);
        let fp = fingerprint(&[
            "bomdrift.young-maintainer",
            purl_or_name,
            &finding.top_contributor,
        ]);
        out.push(json!({
            "ruleId": "bomdrift.young-maintainer",
            "level": "warning",
            "message": {
                "text": format!(
                    "`{name}` top contributor `{}` made their first commit {} day(s) ago \
                     ({}). Investigate maintainer history before merging.",
                    finding.top_contributor,
                    finding.days_old,
                    finding.first_commit_at,
                ),
            },
            "locations": [synthetic_location()],
            "partialFingerprints": { "primaryHash/v1": fp },
            "properties": {
                "purl":           finding.component.purl,
                "name":           name,
                "topContributor": finding.top_contributor,
                "firstCommitAt":  finding.first_commit_at,
                "daysOld":        finding.days_old,
            },
        }));
    }

    // ---- bomdrift.license-change ----
    // license_changed is the suspicious case (license differs at SAME version);
    // version_changed already folds in license-changes-with-version-bumps.
    for (before, after) in &cs.license_changed {
        let name = &after.name;
        let purl_or_name = after.purl.as_deref().unwrap_or(name);
        let mut before_lic = before.licenses.clone();
        before_lic.sort();
        let mut after_lic = after.licenses.clone();
        after_lic.sort();
        let before_join = before_lic.join(",");
        let after_join = after_lic.join(",");
        let fp = fingerprint(&[
            "bomdrift.license-change",
            purl_or_name,
            &before_join,
            &after_join,
        ]);
        out.push(json!({
            "ruleId": "bomdrift.license-change",
            "level": "warning",
            "message": {
                "text": format!(
                    "`{name}` license changed at the same version: {:?} -> {:?}. \
                     Could be a corrected SBOM, a license rug-pull, or a swap.",
                    before.licenses, after.licenses,
                ),
            },
            "locations": [synthetic_location()],
            "partialFingerprints": { "primaryHash/v1": fp },
            "properties": {
                "purl":            after.purl,
                "name":            name,
                "version":         after.version,
                "beforeLicenses":  before.licenses,
                "afterLicenses":   after.licenses,
            },
        }));
    }

    // ---- bomdrift.license-violation ----
    for v in &e.license_violations {
        let name = &v.component.name;
        let purl_or_name = v.component.purl.as_deref().unwrap_or(name);
        let fp = fingerprint(&["bomdrift.license-violation", purl_or_name, &v.license]);
        out.push(json!({
            "ruleId": "bomdrift.license-violation",
            "level": "warning",
            "message": {
                "text": format!(
                    "`{name}` license `{lic}` violates policy ({rule}).",
                    name = name,
                    lic = v.license,
                    rule = v.matched_rule,
                ),
            },
            "locations": [synthetic_location()],
            "partialFingerprints": { "primaryHash/v1": fp },
            "properties": {
                "purl":         v.component.purl,
                "name":         name,
                "version":      v.component.version,
                "license":      v.license,
                "matchedRule":  v.matched_rule,
                "kind":         match v.kind {
                    crate::enrich::LicenseViolationKind::Deny => "deny",
                    crate::enrich::LicenseViolationKind::Ambiguous => "ambiguous",
                    crate::enrich::LicenseViolationKind::NotAllowed => "not-allowed",
                },
            },
        }));
    }

    Value::Array(out)
}

fn synthetic_location() -> Value {
    json!({
        "physicalLocation": {
            "artifactLocation": { "uri": SARIF_ARTIFACT_URI }
        }
    })
}

/// Map our internal [`Severity`] enum to the SARIF `level` enum. Critical and
/// High are the actionable buckets that block-on-merge tooling cares about;
/// everything below collapses to `warning` so reviewers still see the finding
/// without a hard fail in code-scanning views.
fn sarif_level(severity: crate::enrich::Severity) -> &'static str {
    use crate::enrich::Severity;
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium | Severity::Low | Severity::None => "warning",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    use serde_json::Value;

    use crate::enrich::typosquat::TyposquatFinding;
    use crate::enrich::version_jump::VersionJumpFinding;
    use crate::model::{Component, Ecosystem, Relationship};

    fn comp(name: &str, version: &str, eco: Ecosystem, purl: Option<&str>) -> Component {
        Component {
            name: name.to_string(),
            version: version.to_string(),
            ecosystem: eco,
            purl: purl.map(str::to_string),
            licenses: Vec::new(),
            supplier: None,
            hashes: Vec::new(),
            relationship: Relationship::Unknown,
            source_url: None,
            bom_ref: None,
        }
    }

    #[test]
    fn empty_diff_renders_valid_sarif_with_all_rules() {
        let s = render(&ChangeSet::default(), &Enrichment::default());
        let v: Value = serde_json::from_str(&s).expect("output must be valid JSON");
        assert_eq!(v["version"], SARIF_VERSION);
        assert_eq!(v["$schema"], SARIF_SCHEMA);
        let run = &v["runs"][0];
        assert_eq!(run["tool"]["driver"]["name"], "bomdrift");
        assert_eq!(
            run["tool"]["driver"]["semanticVersion"],
            env!("CARGO_PKG_VERSION")
        );
        let rules = run["tool"]["driver"]["rules"].as_array().expect("rules");
        let ids: Vec<&str> = rules.iter().map(|r| r["id"].as_str().unwrap()).collect();
        assert_eq!(
            ids,
            vec![
                "bomdrift.cve",
                "bomdrift.typosquat",
                "bomdrift.version-jump",
                "bomdrift.young-maintainer",
                "bomdrift.license-change",
                "bomdrift.license-violation",
            ],
            "rule IDs are stable public API — order also stable for byte-determinism",
        );
        assert!(
            run["results"].as_array().unwrap().is_empty(),
            "no results when changeset and enrichment are both empty"
        );
    }

    #[test]
    fn cve_results_emit_one_per_advisory_with_purl_property() {
        let mut vulns: HashMap<String, Vec<crate::enrich::VulnRef>> = HashMap::new();
        vulns.insert(
            "pkg:npm/axios@1.14.1".to_string(),
            vec![
                crate::enrich::VulnRef {
                    id: "GHSA-3p68-rc4w-qgx5".to_string(),
                    severity: crate::enrich::Severity::High,
                    aliases: Vec::new(),
                    epss_score: None,
                    kev: false,
                },
                crate::enrich::VulnRef {
                    id: "CVE-2025-99999".to_string(),
                    severity: crate::enrich::Severity::Medium,
                    aliases: Vec::new(),
                    epss_score: None,
                    kev: false,
                },
            ],
        );
        let e = Enrichment {
            vulns,
            ..Default::default()
        };
        let s = render(&ChangeSet::default(), &e);
        let v: Value = serde_json::from_str(&s).unwrap();
        let results = v["runs"][0]["results"].as_array().unwrap();
        assert_eq!(
            results.len(),
            2,
            "one result per (component, advisory) pair"
        );
        // High sorts before Medium.
        assert_eq!(results[0]["ruleId"], "bomdrift.cve");
        assert_eq!(results[0]["level"], "error", "High severity → SARIF error");
        assert_eq!(results[0]["properties"]["purl"], "pkg:npm/axios@1.14.1");
        assert_eq!(
            results[0]["properties"]["advisoryId"],
            "GHSA-3p68-rc4w-qgx5"
        );
        assert_eq!(results[0]["properties"]["severity"], "HIGH");
        assert_eq!(
            results[1]["level"], "warning",
            "Medium severity → SARIF warning"
        );
        // `locations` is required by SARIF; we project to a synthetic `sbom` URI.
        assert_eq!(
            results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "sbom"
        );
    }

    #[test]
    fn cve_severity_none_emits_warning_level() {
        let mut vulns: HashMap<String, Vec<crate::enrich::VulnRef>> = HashMap::new();
        vulns.insert(
            "pkg:npm/x@1".to_string(),
            vec![crate::enrich::VulnRef {
                id: "OSV-2025-1".to_string(),
                severity: crate::enrich::Severity::None,
                aliases: Vec::new(),
                epss_score: None,
                kev: false,
            }],
        );
        let e = Enrichment {
            vulns,
            ..Default::default()
        };
        let s = render(&ChangeSet::default(), &e);
        let v: Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["runs"][0]["results"][0]["level"], "warning");
        assert_eq!(v["runs"][0]["results"][0]["properties"]["severity"], "NONE");
    }

    #[test]
    fn cve_results_are_sorted_by_purl_for_determinism() {
        // HashMap insertion order is non-deterministic, so the renderer must
        // sort the keys before emission. Build the same enrichment twice with
        // different insertion orders and assert byte-identical output.
        let purls = ["pkg:npm/zzz@1", "pkg:npm/mmm@1", "pkg:npm/aaa@1"];
        let make_refs = || {
            vec![crate::enrich::VulnRef {
                id: "CVE-2025-1".to_string(),
                severity: crate::enrich::Severity::Medium,
                aliases: Vec::new(),
                epss_score: None,
                kev: false,
            }]
        };

        let mut a: HashMap<String, Vec<crate::enrich::VulnRef>> = HashMap::new();
        for p in purls {
            a.insert(p.to_string(), make_refs());
        }
        let mut b: HashMap<String, Vec<crate::enrich::VulnRef>> = HashMap::new();
        for p in purls.iter().rev() {
            b.insert(p.to_string(), make_refs());
        }

        let render_a = render(
            &ChangeSet::default(),
            &Enrichment {
                vulns: a,
                ..Default::default()
            },
        );
        let render_b = render(
            &ChangeSet::default(),
            &Enrichment {
                vulns: b,
                ..Default::default()
            },
        );
        assert_eq!(
            render_a, render_b,
            "SARIF output must be byte-deterministic regardless of HashMap insertion order"
        );

        // Spot-check that the order is actually purl-sorted ascending.
        let v: Value = serde_json::from_str(&render_a).unwrap();
        let results = v["runs"][0]["results"].as_array().unwrap();
        let purls_in_order: Vec<&str> = results
            .iter()
            .map(|r| r["properties"]["purl"].as_str().unwrap())
            .collect();
        assert_eq!(
            purls_in_order,
            vec!["pkg:npm/aaa@1", "pkg:npm/mmm@1", "pkg:npm/zzz@1"]
        );
    }

    #[test]
    fn typosquat_result_carries_similarity_and_closest_property() {
        let e = Enrichment {
            typosquats: vec![TyposquatFinding {
                component: comp(
                    "plain-crypto-js",
                    "4.2.1",
                    Ecosystem::Npm,
                    Some("pkg:npm/plain-crypto-js@4.2.1"),
                ),
                closest: "crypto-js".to_string(),
                score: 0.95,
            }],
            ..Default::default()
        };
        let s = render(&ChangeSet::default(), &e);
        let v: Value = serde_json::from_str(&s).unwrap();
        let result = &v["runs"][0]["results"][0];
        assert_eq!(result["ruleId"], "bomdrift.typosquat");
        assert_eq!(result["properties"]["closest"], "crypto-js");
        assert!((result["properties"]["similarity"].as_f64().unwrap() - 0.95).abs() < 1e-9);
        assert_eq!(
            result["properties"]["purl"],
            "pkg:npm/plain-crypto-js@4.2.1"
        );
    }

    #[test]
    fn version_jump_result_carries_major_deltas() {
        let before = comp("foo", "1.0.0", Ecosystem::Npm, Some("pkg:npm/foo@1.0.0"));
        let after = comp("foo", "4.0.0", Ecosystem::Npm, Some("pkg:npm/foo@4.0.0"));
        let e = Enrichment {
            version_jumps: vec![VersionJumpFinding {
                before,
                after,
                before_major: 1,
                after_major: 4,
            }],
            ..Default::default()
        };
        let s = render(&ChangeSet::default(), &e);
        let v: Value = serde_json::from_str(&s).unwrap();
        let result = &v["runs"][0]["results"][0];
        assert_eq!(result["ruleId"], "bomdrift.version-jump");
        assert_eq!(result["properties"]["beforeMajor"], 1);
        assert_eq!(result["properties"]["afterMajor"], 4);
    }

    #[test]
    fn license_change_result_carries_before_after_license_arrays() {
        let mut before = comp("foo", "1.0.0", Ecosystem::Npm, Some("pkg:npm/foo@1.0.0"));
        before.licenses = vec!["MIT".to_string()];
        let mut after = comp("foo", "1.0.0", Ecosystem::Npm, Some("pkg:npm/foo@1.0.0"));
        after.licenses = vec!["GPL-3.0".to_string()];
        let cs = ChangeSet {
            license_changed: vec![(before, after)],
            ..Default::default()
        };
        let s = render(&cs, &Enrichment::default());
        let v: Value = serde_json::from_str(&s).unwrap();
        let result = &v["runs"][0]["results"][0];
        assert_eq!(result["ruleId"], "bomdrift.license-change");
        assert_eq!(result["properties"]["beforeLicenses"][0], "MIT");
        assert_eq!(result["properties"]["afterLicenses"][0], "GPL-3.0");
    }

    #[test]
    fn render_is_pure_byte_deterministic_across_runs() {
        // Regression guard for the upsert contract: identical inputs must
        // render to byte-identical SARIF every time.
        let mut vulns: HashMap<String, Vec<crate::enrich::VulnRef>> = HashMap::new();
        vulns.insert(
            "pkg:npm/axios@1.14.1".to_string(),
            vec![crate::enrich::VulnRef {
                id: "CVE-2025-1".to_string(),
                severity: crate::enrich::Severity::High,
                aliases: Vec::new(),
                epss_score: None,
                kev: false,
            }],
        );
        let e = Enrichment {
            vulns,
            typosquats: vec![TyposquatFinding {
                component: comp(
                    "plain-crypto-js",
                    "4.2.1",
                    Ecosystem::Npm,
                    Some("pkg:npm/plain-crypto-js@4.2.1"),
                ),
                closest: "crypto-js".to_string(),
                score: 0.95,
            }],
            ..Default::default()
        };
        let cs = ChangeSet::default();
        let r1 = render(&cs, &e);
        let r2 = render(&cs, &e);
        let r3 = render(&cs, &e);
        assert_eq!(r1, r2);
        assert_eq!(r2, r3);
    }

    #[test]
    fn output_is_pretty_printed() {
        let s = render(&ChangeSet::default(), &Enrichment::default());
        assert!(s.contains('\n'));
    }

    #[test]
    fn every_result_has_a_location_and_a_ruleid() {
        // SARIF v2.1.0 requires `locations` and `ruleId` (we don't use
        // taxonomies). This is a structural guard so future rule additions
        // can't silently violate the spec.
        let mut vulns: HashMap<String, Vec<crate::enrich::VulnRef>> = HashMap::new();
        vulns.insert(
            "pkg:npm/x@1".into(),
            vec![crate::enrich::VulnRef {
                id: "CVE-1".into(),
                severity: crate::enrich::Severity::Medium,
                aliases: Vec::new(),
                epss_score: None,
                kev: false,
            }],
        );
        let e = Enrichment {
            vulns,
            typosquats: vec![TyposquatFinding {
                component: comp(
                    "squat",
                    "1.0.0",
                    Ecosystem::Npm,
                    Some("pkg:npm/squat@1.0.0"),
                ),
                closest: "real".to_string(),
                score: 0.93,
            }],
            ..Default::default()
        };
        let s = render(&ChangeSet::default(), &e);
        let v: Value = serde_json::from_str(&s).unwrap();
        for result in v["runs"][0]["results"].as_array().unwrap() {
            assert!(result["ruleId"].is_string());
            let locs = result["locations"].as_array().unwrap();
            assert!(!locs.is_empty(), "result missing locations: {result}");
        }
    }

    #[test]
    fn fingerprint_helper_is_pure_and_hex_64_chars() {
        let fp = fingerprint(&["a", "b", "c"]);
        assert_eq!(fp.len(), 64);
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(fp, fingerprint(&["a", "b", "c"]));
        assert_ne!(fp, fingerprint(&["a", "b", "d"]));
        // Joining with `|` matters: ["ab", "c"] must not collide with
        // ["a", "bc"].
        assert_ne!(fingerprint(&["ab", "c"]), fingerprint(&["a", "bc"]));
    }

    #[test]
    fn cve_results_carry_partial_fingerprints_stable_across_runs() {
        let mut vulns: HashMap<String, Vec<crate::enrich::VulnRef>> = HashMap::new();
        vulns.insert(
            "pkg:npm/axios@1.14.1".to_string(),
            vec![crate::enrich::VulnRef {
                id: "GHSA-3p68-rc4w-qgx5".to_string(),
                severity: crate::enrich::Severity::High,
                aliases: Vec::new(),
                epss_score: None,
                kev: false,
            }],
        );
        let e = Enrichment {
            vulns,
            ..Default::default()
        };
        let r1 = render(&ChangeSet::default(), &e);
        let r2 = render(&ChangeSet::default(), &e);
        assert_eq!(r1, r2, "byte-equal across runs");
        let v: Value = serde_json::from_str(&r1).unwrap();
        let fp = &v["runs"][0]["results"][0]["partialFingerprints"]["primaryHash/v1"];
        assert!(fp.is_string(), "fingerprint missing: {}", v);
        assert_eq!(fp.as_str().unwrap().len(), 64);
    }

    #[test]
    fn two_cves_on_same_purl_get_distinct_fingerprints() {
        // The duck flagged this collision case: per-purl-only fingerprints
        // would dedup distinct advisories. Identity must include the
        // advisory id.
        let mut vulns: HashMap<String, Vec<crate::enrich::VulnRef>> = HashMap::new();
        vulns.insert(
            "pkg:npm/axios@1.14.1".to_string(),
            vec![
                crate::enrich::VulnRef {
                    id: "CVE-2025-1".to_string(),
                    severity: crate::enrich::Severity::High,
                    aliases: Vec::new(),
                    epss_score: None,
                    kev: false,
                },
                crate::enrich::VulnRef {
                    id: "CVE-2025-2".to_string(),
                    severity: crate::enrich::Severity::High,
                    aliases: Vec::new(),
                    epss_score: None,
                    kev: false,
                },
            ],
        );
        let e = Enrichment {
            vulns,
            ..Default::default()
        };
        let s = render(&ChangeSet::default(), &e);
        let v: Value = serde_json::from_str(&s).unwrap();
        let results = v["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 2);
        let f1 = results[0]["partialFingerprints"]["primaryHash/v1"]
            .as_str()
            .unwrap();
        let f2 = results[1]["partialFingerprints"]["primaryHash/v1"]
            .as_str()
            .unwrap();
        assert_ne!(
            f1, f2,
            "distinct advisories must have distinct fingerprints"
        );
    }

    #[test]
    fn version_jump_fingerprint_uses_full_versions_not_majors() {
        // 1.0.0 -> 4.0.0 and 1.5.0 -> 4.5.0 both have major delta 3 but
        // are distinct findings — fingerprints must not collide.
        let mk = |a: &str, b: &str| VersionJumpFinding {
            before: comp("foo", a, Ecosystem::Npm, Some("pkg:npm/foo@1")),
            after: comp("foo", b, Ecosystem::Npm, Some("pkg:npm/foo@4")),
            before_major: 1,
            after_major: 4,
        };
        let e1 = Enrichment {
            version_jumps: vec![mk("1.0.0", "4.0.0")],
            ..Default::default()
        };
        let e2 = Enrichment {
            version_jumps: vec![mk("1.5.0", "4.5.0")],
            ..Default::default()
        };
        let v1: Value = serde_json::from_str(&render(&ChangeSet::default(), &e1)).unwrap();
        let v2: Value = serde_json::from_str(&render(&ChangeSet::default(), &e2)).unwrap();
        let f1 = v1["runs"][0]["results"][0]["partialFingerprints"]["primaryHash/v1"]
            .as_str()
            .unwrap()
            .to_string();
        let f2 = v2["runs"][0]["results"][0]["partialFingerprints"]["primaryHash/v1"]
            .as_str()
            .unwrap()
            .to_string();
        assert_ne!(f1, f2);
    }

    #[test]
    fn license_violation_emits_result_with_stable_fingerprint() {
        use crate::enrich::{LicenseViolation, LicenseViolationKind};
        let comp = comp("foo", "1.0.0", Ecosystem::Npm, Some("pkg:npm/foo@1.0.0"));
        let e = Enrichment {
            license_violations: vec![LicenseViolation {
                component: comp,
                license: "GPL-3.0-only".into(),
                matched_rule: "deny: GPL-3.0-only".into(),
                kind: LicenseViolationKind::Deny,
            }],
            ..Default::default()
        };
        let r1 = render(&ChangeSet::default(), &e);
        let r2 = render(&ChangeSet::default(), &e);
        assert_eq!(r1, r2, "byte-equal across runs");
        let v: Value = serde_json::from_str(&r1).unwrap();
        let result = &v["runs"][0]["results"][0];
        assert_eq!(result["ruleId"], "bomdrift.license-violation");
        assert_eq!(result["properties"]["license"], "GPL-3.0-only");
        assert_eq!(result["properties"]["kind"], "deny");
        assert_eq!(
            result["partialFingerprints"]["primaryHash/v1"]
                .as_str()
                .unwrap()
                .len(),
            64
        );
    }
}
