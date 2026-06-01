#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented
)]
use std::collections::HashMap;

use super::calibration::{CalibrationOverrides, write_calibration_lines};
use super::predicates::{any_epss_at_or_above, budget_tripped, tripped};

use crate::cli::FailOn;
use crate::diff::ChangeSet;
use crate::enrich::typosquat::TyposquatFinding;
use crate::enrich::version_jump::VersionJumpFinding;
use crate::enrich::{Enrichment, LicenseViolation, Severity, VulnRef};
use crate::model::{Component, Ecosystem, Relationship};

fn comp(name: &str) -> Component {
    Component {
        name: name.to_string(),
        version: "1.0.0".to_string(),
        ecosystem: Ecosystem::Npm,
        purl: Some(format!("pkg:npm/{name}@1.0.0")),
        licenses: Vec::new(),
        supplier: None,
        hashes: Vec::new(),
        relationship: Relationship::Unknown,
        source_url: None,
        bom_ref: None,
    }
}

fn enrichment_with_cve_at(severity: Severity) -> Enrichment {
    let mut vulns: HashMap<String, Vec<VulnRef>> = HashMap::new();
    vulns.insert(
        "pkg:npm/foo@1.0.0".into(),
        vec![VulnRef {
            id: "CVE-2025-1".into(),
            severity,
            aliases: Vec::new(),
            epss_score: None,
            kev: false,
        }],
    );
    Enrichment {
        vulns,
        ..Default::default()
    }
}

fn enrichment_with_cve() -> Enrichment {
    // Severity::None is what every v0.2-era test implicitly assumed — the
    // pre-severity world. Tests that don't care about the bucket use this.
    enrichment_with_cve_at(Severity::None)
}

fn enrichment_with_typosquat() -> Enrichment {
    Enrichment {
        typosquats: vec![TyposquatFinding {
            component: comp("plain-crypto-js"),
            closest: "crypto-js".to_string(),
            score: 0.95,
        }],
        ..Default::default()
    }
}

fn enrichment_with_version_jump() -> Enrichment {
    Enrichment {
        version_jumps: vec![VersionJumpFinding {
            before: comp("foo"),
            after: comp("foo"),
            before_major: 1,
            after_major: 4,
        }],
        ..Default::default()
    }
}

fn cs_with_license_change() -> ChangeSet {
    let mut before = comp("foo");
    before.licenses = vec!["MIT".into()];
    let mut after = comp("foo");
    after.licenses = vec!["GPL-3.0".into()];
    ChangeSet {
        license_changed: vec![(before, after)],
        ..Default::default()
    }
}

#[test]
fn fail_on_none_never_trips() {
    assert!(!tripped(
        &ChangeSet::default(),
        &Enrichment::default(),
        FailOn::None
    ));
    assert!(!tripped(
        &cs_with_license_change(),
        &enrichment_with_cve(),
        FailOn::None
    ));
}

#[test]
fn fail_on_cve_trips_only_on_cve_findings() {
    assert!(tripped(
        &ChangeSet::default(),
        &enrichment_with_cve(),
        FailOn::Cve
    ));
    assert!(!tripped(
        &ChangeSet::default(),
        &enrichment_with_typosquat(),
        FailOn::Cve
    ));
    assert!(!tripped(
        &ChangeSet::default(),
        &Enrichment::default(),
        FailOn::Cve
    ));
}

#[test]
fn fail_on_critical_cve_filters_on_severity_high_or_above() {
    // Critical and High advisories trip; Medium / Low / None don't. The
    // doc on `tripped()` explains why High is included in the
    // "critical-cve" bucket.
    assert!(tripped(
        &ChangeSet::default(),
        &enrichment_with_cve_at(Severity::Critical),
        FailOn::CriticalCve
    ));
    assert!(tripped(
        &ChangeSet::default(),
        &enrichment_with_cve_at(Severity::High),
        FailOn::CriticalCve
    ));
    assert!(!tripped(
        &ChangeSet::default(),
        &enrichment_with_cve_at(Severity::Medium),
        FailOn::CriticalCve
    ));
    assert!(!tripped(
        &ChangeSet::default(),
        &enrichment_with_cve_at(Severity::None),
        FailOn::CriticalCve
    ));
}

#[test]
fn fail_on_cve_still_trips_on_severity_none_advisories() {
    // --fail-on cve is the broad "any advisory" bucket; severity threading
    // doesn't change its semantics. An advisory with unresolved severity
    // still trips it (the alternative — silent suppression — would be the
    // real footgun).
    assert!(tripped(
        &ChangeSet::default(),
        &enrichment_with_cve_at(Severity::None),
        FailOn::Cve
    ));
}

#[test]
fn fail_on_typosquat_trips_only_on_typosquat_findings() {
    assert!(tripped(
        &ChangeSet::default(),
        &enrichment_with_typosquat(),
        FailOn::Typosquat
    ));
    assert!(!tripped(
        &ChangeSet::default(),
        &enrichment_with_cve(),
        FailOn::Typosquat
    ));
}

#[test]
fn fail_on_any_trips_on_each_finding_kind_and_license_changes() {
    assert!(tripped(
        &ChangeSet::default(),
        &enrichment_with_cve(),
        FailOn::Any
    ));
    assert!(tripped(
        &ChangeSet::default(),
        &enrichment_with_typosquat(),
        FailOn::Any
    ));
    assert!(tripped(
        &ChangeSet::default(),
        &enrichment_with_version_jump(),
        FailOn::Any
    ));
    // license-changed-without-version-bump alone trips Any (the suspicious
    // case lives on the ChangeSet, not the enrichment).
    assert!(tripped(
        &cs_with_license_change(),
        &Enrichment::default(),
        FailOn::Any
    ));
    assert!(!tripped(
        &ChangeSet::default(),
        &Enrichment::default(),
        FailOn::Any
    ));
}

#[test]
fn fail_on_license_change_trips_only_on_license_changes() {
    assert!(tripped(
        &cs_with_license_change(),
        &Enrichment::default(),
        FailOn::LicenseChange
    ));
    assert!(!tripped(
        &ChangeSet::default(),
        &enrichment_with_cve(),
        FailOn::LicenseChange
    ));
    assert!(!tripped(
        &ChangeSet::default(),
        &enrichment_with_typosquat(),
        FailOn::LicenseChange
    ));
}

#[test]
fn fail_on_typosquat_ignores_license_change() {
    // license_changed is a ChangeSet field, not an enrichment. The
    // typosquat threshold is strictly about typosquat findings — license
    // drift must NOT trip it (otherwise consumers using --fail-on=typosquat
    // get unexpected exit-2's on every license correction).
    assert!(!tripped(
        &cs_with_license_change(),
        &Enrichment::default(),
        FailOn::Typosquat
    ));
}

#[test]
fn budget_trips_when_counts_exceed_limits() {
    let cs = ChangeSet {
        added: vec![comp("a"), comp("b")],
        removed: vec![comp("c")],
        version_changed: vec![(comp("d"), comp("d"))],
        ..Default::default()
    };
    assert!(budget_tripped(&cs, Some(1), None, None));
    assert!(budget_tripped(&cs, None, Some(0), None));
    assert!(budget_tripped(&cs, None, None, Some(0)));
    assert!(!budget_tripped(&cs, Some(2), Some(1), Some(1)));
}

#[test]
fn calibration_pipe_format_matches_v0_7_layout() {
    let e = enrichment_with_typosquat();
    let mut buf = Vec::new();
    write_calibration_lines(
        &e,
        &mut buf,
        crate::cli::DebugFormat::Pipe,
        CalibrationOverrides::default(),
    );
    let s = String::from_utf8(buf).unwrap();
    assert!(s.starts_with("typosquat|"), "got: {s}");
    assert_eq!(
        s.matches('|').count(),
        3,
        "pipe row has 4 fields → 3 separators; got: {s}"
    );
}

#[test]
fn calibration_jsonl_format_emits_one_object_per_line() {
    let e = enrichment_with_typosquat();
    let mut buf = Vec::new();
    write_calibration_lines(
        &e,
        &mut buf,
        crate::cli::DebugFormat::Jsonl,
        CalibrationOverrides::default(),
    );
    let s = String::from_utf8(buf).unwrap();
    let lines: Vec<&str> = s.lines().collect();
    assert_eq!(lines.len(), 1);
    let v: serde_json::Value = serde_json::from_str(lines[0]).expect("valid jsonl");
    assert_eq!(v["kind"], "typosquat");
    assert!(v["score"].is_number(), "numeric score in jsonl");
    assert!(v["threshold"].is_number());
    assert!(v["key"].is_string());
}

#[test]
fn calibration_jsonl_keeps_severity_label_as_string() {
    let e = enrichment_with_cve_at(Severity::High);
    let mut buf = Vec::new();
    write_calibration_lines(
        &e,
        &mut buf,
        crate::cli::DebugFormat::Jsonl,
        CalibrationOverrides::default(),
    );
    let s = String::from_utf8(buf).unwrap();
    let v: serde_json::Value = serde_json::from_str(s.trim()).unwrap();
    assert_eq!(v["kind"], "cve");
    assert_eq!(v["score"], "HIGH");
    assert_eq!(v["threshold"], "high+");
}

#[test]
fn fail_on_kev_trips_when_any_advisory_kev_set() {
    let mut e = enrichment_with_cve_at(Severity::Medium);
    // Flip the kev flag on the single advisory.
    for refs in e.vulns.values_mut() {
        refs[0].kev = true;
    }
    assert!(tripped(&ChangeSet::default(), &e, FailOn::Kev));
    assert!(!tripped(
        &ChangeSet::default(),
        &enrichment_with_cve_at(Severity::Medium),
        FailOn::Kev
    ));
}

#[test]
fn any_epss_threshold_gating() {
    let mut e = enrichment_with_cve_at(Severity::Medium);
    for refs in e.vulns.values_mut() {
        refs[0].epss_score = Some(0.6);
    }
    assert!(any_epss_at_or_above(&e, 0.5));
    assert!(any_epss_at_or_above(&e, 0.6));
    assert!(!any_epss_at_or_above(&e, 0.7));
}

#[test]
fn calibration_emits_epss_and_kev_rows_when_set() {
    let mut e = enrichment_with_cve_at(Severity::High);
    for refs in e.vulns.values_mut() {
        refs[0].epss_score = Some(0.87);
        refs[0].kev = true;
    }
    let mut buf = Vec::new();
    write_calibration_lines(
        &e,
        &mut buf,
        crate::cli::DebugFormat::Pipe,
        CalibrationOverrides::default(),
    );
    let s = String::from_utf8(buf).unwrap();
    assert!(s.contains("epss|"), "missing epss row: {s}");
    assert!(s.contains("kev|"), "missing kev row: {s}");
}

#[test]
fn calibration_license_row_includes_exception_detail() {
    // v0.9.5: matched_rule on an exception-driven license violation
    // must surface the exception identifier in the calibration tap
    // so operators tuning policy see why a row fired.
    let mut e = Enrichment::default();
    let component = crate::model::Component {
        name: "llvm-sys".into(),
        version: "1.0.0".into(),
        ecosystem: crate::model::Ecosystem::Cargo,
        purl: Some("pkg:cargo/llvm-sys@1.0.0".into()),
        licenses: vec!["Apache-2.0 WITH LLVM-exception".into()],
        supplier: None,
        hashes: Vec::new(),
        relationship: crate::model::Relationship::Unknown,
        source_url: None,
        bom_ref: None,
    };
    e.license_violations.push(LicenseViolation {
        component,
        license: "Apache-2.0 WITH LLVM-exception".into(),
        matched_rule: "exception:LLVM-exception denied".into(),
        kind: crate::enrich::LicenseViolationKind::Deny,
    });
    let mut buf = Vec::new();
    write_calibration_lines(
        &e,
        &mut buf,
        crate::cli::DebugFormat::Pipe,
        CalibrationOverrides::default(),
    );
    let s = String::from_utf8(buf).unwrap();
    assert!(
        s.contains("license|"),
        "missing license calibration row: {s}"
    );
    assert!(
        s.contains("exception:LLVM-exception denied"),
        "row must surface matched_rule with exception detail: {s}"
    );
}

#[test]
fn fail_on_license_violation_trips() {
    use crate::enrich::{LicenseViolation, LicenseViolationKind};
    let mut e = Enrichment::default();
    e.license_violations.push(LicenseViolation {
        component: comp("foo"),
        license: "GPL-3.0-only".into(),
        matched_rule: "deny: GPL-3.0-only".into(),
        kind: LicenseViolationKind::Deny,
    });
    assert!(tripped(&ChangeSet::default(), &e, FailOn::LicenseViolation));
    assert!(tripped(&ChangeSet::default(), &e, FailOn::Any));
    assert!(!tripped(
        &ChangeSet::default(),
        &Enrichment::default(),
        FailOn::LicenseViolation
    ));
}
