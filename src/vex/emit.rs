//! OpenVEX 0.2.0 emission. See [`emit`] for the entry point used by the
//! `--emit-vex` CLI flag.

use super::{VexStatus, synthetic_id};

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
    #[allow(
        clippy::expect_used,
        reason = "invariant: serde_json::to_string_pretty cannot fail on a Value built from owned data with string keys"
    )]
    serde_json::to_string_pretty(&doc)
        .expect("invariant: serde_json::to_string_pretty cannot fail on a Value built from owned data with string keys")
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::todo,
        clippy::unimplemented
    )]
    use super::super::load;
    use super::*;

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
        // SAFETY: caller must hold the `pin_clock` mutex guard for the
        // duration of this call so env mutation stays serialized.
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
}
