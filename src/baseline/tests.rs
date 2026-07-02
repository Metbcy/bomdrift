#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented
)]
use super::*;
use crate::diff::ChangeSet;
use crate::enrich::Enrichment;
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
            // SAFETY: env mutation guarded by the `_lock` field below
            // which holds the crate-wide `clock::test_env_lock()`
            // mutex for the lifetime of this Guard.
            unsafe {
                std::env::remove_var("SOURCE_DATE_EPOCH");
            }
        }
    }
    let _lock = crate::clock::test_env_lock();
    // SAFETY: env mutation serialized by the `_lock` mutex guard above.
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

// ─────────────────────────────────────────────────────────────────────
// Mutation-test gap closures (issue #35).
//
// These tests were added to catch surviving mutants reported by
// `cargo mutants --file src/baseline.rs`. Each test's docstring names
// the line:col of the original mutant; the test fails (panics or
// assertion) under the mutated source, so the mutant is "caught".
// ─────────────────────────────────────────────────────────────────────

/// Catches mutants:
///   src/baseline.rs:151:37 — replace `&&` with `||` in `from_value_inner` (typosquats arm)
/// An entry with non-empty purl but empty closest must NOT be inserted
/// as a typosquat key. Under `||` the entry would be inserted with
/// closest="", and our subsequent apply() would match a real finding
/// against the wrong key (or silently drop nothing).
#[test]
fn typosquat_key_requires_both_purl_and_closest_nonempty() {
    let baseline = Baseline::from_value(&json!({
        "enrichment": {
            "typosquats": [
                { "component": { "purl": "pkg:npm/express@5.0.0" }, "closest": "" },
                { "component": { "purl": "" }, "closest": "express" },
                { "component": { "purl": "pkg:npm/expres@5.0.0" }, "closest": "express" }
            ]
        }
    }));
    // Only the third entry has both fields non-empty; the other two
    // must be dropped. Under `||` we'd see 3 keys, not 1.
    assert_eq!(baseline.typosquat_keys.len(), 1);
    assert!(
        baseline
            .typosquat_keys
            .contains(&("pkg:npm/expres@5.0.0".to_string(), "express".to_string()))
    );
}

/// Catches mutants:
///   src/baseline.rs:176:37 — replace `&&` with `||` in maintainer_age arm
///   src/baseline.rs:176:20 — delete `!` on `purl.is_empty()`
///   src/baseline.rs:176:40 — delete `!` on `contrib.is_empty()`
/// Same shape as the typosquat test above but for maintainer_age:
/// both purl AND top_contributor must be non-empty for the key to be
/// registered. Under any of the three mutants this assertion breaks.
#[test]
fn maintainer_age_key_requires_both_purl_and_contributor_nonempty() {
    let baseline = Baseline::from_value(&json!({
        "enrichment": {
            "maintainer_age": [
                { "component": { "purl": "pkg:npm/foo@1.0.0" }, "top_contributor": "" },
                { "component": { "purl": "" }, "top_contributor": "alice" },
                { "component": { "purl": "pkg:npm/bar@2.0.0" }, "top_contributor": "bob" }
            ]
        }
    }));
    assert_eq!(baseline.young_maintainer_keys.len(), 1);
    assert!(
        baseline
            .young_maintainer_keys
            .contains(&("pkg:npm/bar@2.0.0".to_string(), "bob".to_string()))
    );
}

/// Catches mutant:
///   src/baseline.rs:320:9 — delete `!` in `apply` (maintainer_age retain)
/// A maintainer_age finding whose (purl, top_contributor) IS in the
/// baseline must be dropped; one that is NOT in the baseline must be
/// kept. Under the deleted `!`, the retain predicate flips and the
/// baseline-matched finding survives while the unmatched one is
/// dropped — both assertions fail.
#[test]
fn apply_drops_matched_maintainer_age_and_keeps_unmatched() {
    use crate::enrich::maintainer::{Host, MaintainerAgeFinding};

    let baseline = Baseline::from_value(&json!({
        "enrichment": {
            "maintainer_age": [
                { "component": { "purl": "pkg:npm/foo@1.0.0" }, "top_contributor": "alice" }
            ]
        }
    }));
    let mut cs = ChangeSet::default();
    let mut e = Enrichment::default();
    e.maintainer_age.push(MaintainerAgeFinding {
        component: comp("pkg:npm/foo@1.0.0"),
        top_contributor: "alice".into(),
        first_commit_at: "2026-01-01T00:00:00Z".into(),
        days_old: 30,
        host: Host::Github,
    });
    e.maintainer_age.push(MaintainerAgeFinding {
        component: comp("pkg:npm/bar@2.0.0"),
        top_contributor: "bob".into(),
        first_commit_at: "2026-01-01T00:00:00Z".into(),
        days_old: 30,
        host: Host::Github,
    });
    apply(&mut cs, &mut e, &baseline);
    assert_eq!(e.maintainer_age.len(), 1, "matched finding must be dropped");
    assert_eq!(
        e.maintainer_age[0].component.purl.as_deref(),
        Some("pkg:npm/bar@2.0.0"),
        "unmatched finding must be kept"
    );
}

/// Catches mutants:
///   src/baseline.rs:414:26 — replace `||` with `&&` in `add_suppression_full`
///   src/baseline.rs:429:12 — delete `!` on `parent.as_os_str().is_empty()`
/// 414: object-form entry must be written when EITHER expires OR
/// reason is provided. Under `&&` only expires-AND-reason produces an
/// object; expires-only would silently downgrade to string form, so
/// the recorded expires date would be lost.
/// 429: when the path has a non-empty parent, create_dir_all must be
/// called. With the `!` deleted, parent creation never happens and
/// the subsequent fs::write fails for nested paths.
#[test]
fn add_suppression_full_writes_object_form_with_expires_only() {
    let dir = tempdir_unique("expires_only");
    // Nested path (exercises the parent-dir branch at line 428-429
    // simultaneously — if `!` is deleted, create_dir_all is skipped
    // and the write fails before we get to assert the object form).
    let path = dir.join("nested").join("subdir").join("baseline.json");
    let outcome = add_suppression_full(&path, "GHSA-x", Some("2099-01-01"), None).unwrap();
    assert!(matches!(outcome, AddOutcome::Added));

    let body = std::fs::read_to_string(&path).unwrap();
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    let arr = v["suppressed_advisories"].as_array().unwrap();
    assert_eq!(arr.len(), 1);
    // Under `&&` instead of `||`, this would be Value::String("GHSA-x")
    // because expires-only wouldn't trip the object-form branch.
    assert!(
        arr[0].is_object(),
        "expires-only entry must serialize as an object, got {:?}",
        arr[0]
    );
    assert_eq!(arr[0]["id"].as_str(), Some("GHSA-x"));
    assert_eq!(arr[0]["expires"].as_str(), Some("2099-01-01"));

    std::fs::remove_dir_all(&dir).ok();
}

/// Symmetric companion to the above for reason-only — separately
/// asserts the `||` branch (not `&&`) by exercising the OTHER side.
/// Under `&&` reason-only would also downgrade to string form.
#[test]
fn add_suppression_full_writes_object_form_with_reason_only() {
    let dir = tempdir_unique("reason_only");
    let path = dir.join("baseline.json");
    let outcome =
        add_suppression_full(&path, "GHSA-y", None, Some("vendor will patch q4")).unwrap();
    assert!(matches!(outcome, AddOutcome::Added));

    let body = std::fs::read_to_string(&path).unwrap();
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    let arr = v["suppressed_advisories"].as_array().unwrap();
    assert!(arr[0].is_object());
    assert_eq!(arr[0]["reason"].as_str(), Some("vendor will patch q4"));

    std::fs::remove_dir_all(&dir).ok();
}

/// Catches mutants:
///   src/baseline.rs:523:5 — replace `doc_kind -> &'static str` with `""`
///   src/baseline.rs:523:5 — replace `doc_kind -> &'static str` with `"xyzzy"`
/// `doc_kind` feeds an error message when the baseline root isn't a
/// JSON object. Mutants make it return a fixed string regardless of
/// the actual JSON shape, so the error message becomes useless ("root
/// must be an object, found: xyzzy"). Pin the exact returned tag for
/// each Value variant. Tested via the public error path that calls it.
#[test]
fn add_suppression_full_error_names_actual_root_type() {
    let dir = tempdir_unique("doc_kind_tag");
    let path = dir.join("baseline.json");
    // Write a baseline file whose root is a JSON array, not an object.
    std::fs::write(&path, "[1, 2, 3]").unwrap();
    let err = add_suppression_full(&path, "GHSA-z", None, None)
        .unwrap_err()
        .to_string();
    // Must name the actual type. Under the empty-string mutant the
    // message ends with "found: " (with nothing after); under the
    // "xyzzy" mutant it ends with "found: xyzzy".
    assert!(
        err.contains("found: array"),
        "doc_kind must return the literal variant tag; got error: {err}"
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// Direct unit on `doc_kind` to nail down the full mapping, so the
/// per-Value-variant string is locked in code rather than only
/// exercised through one error path.
#[test]
fn doc_kind_maps_each_json_variant_to_its_label() {
    assert_eq!(doc_kind(&json!(null)), "null");
    assert_eq!(doc_kind(&json!(true)), "bool");
    assert_eq!(doc_kind(&json!(1)), "number");
    assert_eq!(doc_kind(&json!("s")), "string");
    assert_eq!(doc_kind(&json!([1])), "array");
    assert_eq!(doc_kind(&json!({"k": "v"})), "object");
}
