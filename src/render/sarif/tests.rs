#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented
)]
use super::*;
use std::collections::HashMap;

use serde_json::Value;

use crate::diff::ChangeSet;
use crate::enrich::Enrichment;
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
            "bomdrift.recently-published",
            "bomdrift.deprecated",
            "bomdrift.maintainer-set-changed",
            "bomdrift.plugin",
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
    assert!(fp.is_string(), "fingerprint missing: {v}");
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

#[test]
fn exception_driven_license_violation_fingerprint_differs_from_base() {
    // v0.9.5: a violation driven by a denied SPDX `WITH` exception
    // must have a stable partialFingerprint distinct from a
    // base-license violation on the same component, so SARIF
    // consumers (Code Scanning) treat them as separate alerts.
    use crate::enrich::{LicenseViolation, LicenseViolationKind};
    let component = comp("foo", "1.0.0", Ecosystem::Npm, Some("pkg:npm/foo@1.0.0"));
    let e_exception = Enrichment {
        license_violations: vec![LicenseViolation {
            component: component.clone(),
            license: "Apache-2.0 WITH LLVM-exception".into(),
            matched_rule: "exception:LLVM-exception denied".into(),
            kind: LicenseViolationKind::Deny,
        }],
        ..Default::default()
    };
    let e_base = Enrichment {
        license_violations: vec![LicenseViolation {
            component,
            license: "Apache-2.0".into(),
            matched_rule: "deny: Apache-2.0".into(),
            kind: LicenseViolationKind::Deny,
        }],
        ..Default::default()
    };
    let r_exception = render(&ChangeSet::default(), &e_exception);
    let r_base = render(&ChangeSet::default(), &e_base);
    let parse = |s: &str| -> String {
        let v: Value = serde_json::from_str(s).unwrap();
        v["runs"][0]["results"][0]["partialFingerprints"]["primaryHash/v1"]
            .as_str()
            .unwrap()
            .to_string()
    };
    let fp_ex = parse(&r_exception);
    let fp_base = parse(&r_base);
    assert_ne!(
        fp_ex, fp_base,
        "exception-driven violation fingerprint must differ from base-license violation"
    );
    // Stable across runs.
    let r_exception_2 = render(&ChangeSet::default(), &e_exception);
    assert_eq!(parse(&r_exception_2), fp_ex);
}

#[test]
fn plugin_findings_emit_sarif_results_with_distinct_fingerprints() {
    use crate::plugin::{PluginFinding, PluginSeverity};
    let mut e = Enrichment::default();
    e.plugin_findings.push(PluginFinding {
        plugin_name: "banned".into(),
        component_purl: "pkg:npm/left-pad@1.0.0".into(),
        kind: "banned-package".into(),
        message: "left-pad is banned".into(),
        severity: PluginSeverity::Warning,
        rule_id: "banned/left-pad".into(),
    });
    e.plugin_findings.push(PluginFinding {
        plugin_name: "banned".into(),
        component_purl: "pkg:npm/right-pad@2.0.0".into(),
        kind: "banned-package".into(),
        message: "right-pad is banned".into(),
        severity: PluginSeverity::Error,
        rule_id: "banned/right-pad".into(),
    });
    let s = render(&ChangeSet::default(), &e);
    let v: Value = serde_json::from_str(&s).unwrap();
    let results = v["runs"][0]["results"].as_array().unwrap();
    let plugin_results: Vec<&Value> = results
        .iter()
        .filter(|r| r["ruleId"] == "bomdrift.plugin")
        .collect();
    assert_eq!(plugin_results.len(), 2);

    let fp1 = plugin_results[0]["partialFingerprints"]["primaryHash/v1"]
        .as_str()
        .unwrap();
    let fp2 = plugin_results[1]["partialFingerprints"]["primaryHash/v1"]
        .as_str()
        .unwrap();
    assert_ne!(fp1, fp2, "distinct fingerprints per (purl, rule_id)");
    assert_eq!(plugin_results[0]["properties"]["pluginName"], "banned");
    assert_eq!(
        plugin_results[0]["properties"]["findingKind"],
        "banned-package"
    );
    assert_eq!(plugin_results[1]["level"], "error");

    // Render twice must produce byte-equal output.
    let s2 = render(&ChangeSet::default(), &e);
    assert_eq!(s, s2);
}
