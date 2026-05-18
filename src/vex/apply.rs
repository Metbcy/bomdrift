//! Apply a built VEX index to an enrichment result: drop findings whose
//! statements say `not_affected`/`fixed`, annotate findings whose
//! statements say `affected`/`under_investigation`.

use super::{VexAnnotation, VexIndex, synthetic_id};

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
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::todo,
        clippy::unimplemented
    )]
    use super::*;
    use crate::enrich::{
        Enrichment, LicenseViolation, LicenseViolationKind, Severity, VulnRef,
        maintainer::MaintainerAgeFinding, typosquat::TyposquatFinding,
        version_jump::VersionJumpFinding,
    };
    use crate::model::{Component, Ecosystem, Relationship};
    use crate::vex::{VexStatement, VexStatus};

    fn comp(purl: &str, name: &str, version: &str) -> Component {
        Component {
            name: name.into(),
            version: version.into(),
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

    fn stmt(vuln_id: &str, product: &str, status: VexStatus) -> VexStatement {
        VexStatement {
            vuln_id: vuln_id.into(),
            products: vec![product.into()],
            status,
            justification: Some("vulnerable_code_not_present".into()),
            status_notes: None,
        }
    }

    /// Empty-index fast path returns without touching the enrichment.
    #[test]
    fn apply_noop_on_empty_index() {
        let mut e = Enrichment::default();
        let purl = "pkg:npm/foo@1.0.0".to_string();
        e.vulns.insert(
            purl.clone(),
            vec![VulnRef::new("CVE-2024-1", Severity::High)],
        );
        let before = e.vulns.get(&purl).map(|v| v.len()).unwrap_or(0);

        apply(&mut e, &VexIndex::build(Vec::new()));

        assert_eq!(e.vex_suppressed_count, 0);
        assert!(e.vex_annotations.is_empty());
        assert_eq!(e.vulns.get(&purl).map(|v| v.len()).unwrap_or(0), before);
    }

    /// Vulns branch: suppression decrements the per-purl vec, retains() drops
    /// the empty entry, suppressed counter increments by exactly 1, and an
    /// `affected` vuln on the same purl is annotated (not suppressed).
    /// Kills: `replace apply with ()`, `delete !` at line 40, `+= -=/`,
    /// `apply::is_empty -> true/false` mutants on the early-return path.
    #[test]
    fn apply_vulns_suppresses_and_annotates() {
        let mut e = Enrichment::default();
        let purl = "pkg:npm/foo@1.0.0".to_string();
        e.vulns.insert(
            purl.clone(),
            vec![
                VulnRef::new("CVE-SUPPRESS", Severity::High),
                VulnRef::new("CVE-ANNOTATE", Severity::Medium),
            ],
        );
        // A second purl with only a suppressed vuln — its key should be
        // removed entirely by the retain(!is_empty) pass.
        let purl_empty = "pkg:npm/bar@2.0.0".to_string();
        e.vulns.insert(
            purl_empty.clone(),
            vec![VulnRef::new("CVE-GONE", Severity::Critical)],
        );

        let idx = VexIndex::build(vec![
            stmt("CVE-SUPPRESS", &purl, VexStatus::NotAffected),
            stmt("CVE-ANNOTATE", &purl, VexStatus::Affected),
            stmt("CVE-GONE", &purl_empty, VexStatus::Fixed),
        ]);

        apply(&mut e, &idx);

        // Counter went up by exactly 2 suppressions (kills += -=/*= mutants
        // on the vulns branch).
        assert_eq!(e.vex_suppressed_count, 2);
        // Empty-purl key removed by retain(!is_empty) — kills `delete !`.
        assert!(!e.vulns.contains_key(&purl_empty));
        // Suppressed vuln dropped from purl1, annotated vuln retained.
        let remaining = e.vulns.get(&purl).expect("purl key still present");
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].id, "CVE-ANNOTATE");
        // Annotation written under `cve:<purl>:<id>` key.
        let ann_key = format!("cve:{purl}:CVE-ANNOTATE");
        assert!(
            e.vex_annotations.contains_key(&ann_key),
            "expected annotation key {ann_key} in {:?}",
            e.vex_annotations.keys().collect::<Vec<_>>()
        );
        let ann = &e.vex_annotations[&ann_key];
        assert_eq!(ann.status, "affected");
    }

    /// Typosquat branch: suppression drops the finding and bumps the counter.
    /// Kills the `+=` mutants on line 53.
    #[test]
    fn apply_typosquats_suppresses_and_counts() {
        let mut e = Enrichment::default();
        let purl = "pkg:npm/plain-crypto-js@4.2.1";
        let kept_purl = "pkg:npm/lodahs@1.0.0";
        e.typosquats = vec![
            TyposquatFinding {
                component: comp(purl, "plain-crypto-js", "4.2.1"),
                closest: "crypto-js".into(),
                score: 0.95,
            },
            TyposquatFinding {
                component: comp(kept_purl, "lodahs", "1.0.0"),
                closest: "lodash".into(),
                score: 0.9,
            },
        ];

        // Only suppress the first one.
        let id = crate::vex::synthetic_id::typosquat(&e.typosquats[0]);
        let idx = VexIndex::build(vec![stmt(&id, purl, VexStatus::NotAffected)]);

        apply(&mut e, &idx);

        assert_eq!(e.vex_suppressed_count, 1);
        assert_eq!(e.typosquats.len(), 1);
        assert_eq!(e.typosquats[0].closest, "lodash");
    }

    /// Typosquat annotation path (not suppressed) writes to vex_annotations
    /// under the synthetic id and keeps the finding in place.
    #[test]
    fn apply_typosquats_annotates_under_investigation() {
        let mut e = Enrichment::default();
        let purl = "pkg:npm/reqeusts@2.0.0";
        e.typosquats = vec![TyposquatFinding {
            component: comp(purl, "reqeusts", "2.0.0"),
            closest: "requests".into(),
            score: 0.92,
        }];
        let id = crate::vex::synthetic_id::typosquat(&e.typosquats[0]);
        let idx = VexIndex::build(vec![stmt(&id, purl, VexStatus::UnderInvestigation)]);

        apply(&mut e, &idx);

        assert_eq!(e.vex_suppressed_count, 0);
        assert_eq!(e.typosquats.len(), 1);
        assert!(e.vex_annotations.contains_key(&id));
        assert_eq!(e.vex_annotations[&id].status, "under_investigation");
    }

    /// Version-jump branch: suppression drops and counts. Kills `+=` mutants
    /// at line 77.
    #[test]
    fn apply_version_jumps_suppresses_and_counts() {
        let mut e = Enrichment::default();
        let before_purl = "pkg:npm/lib@1.0.0";
        let after_purl = "pkg:npm/lib@4.0.0";
        e.version_jumps = vec![VersionJumpFinding {
            before: comp(before_purl, "lib", "1.0.0"),
            after: comp(after_purl, "lib", "4.0.0"),
            before_major: 1,
            after_major: 4,
        }];
        let id = crate::vex::synthetic_id::version_jump(&e.version_jumps[0]);
        let idx = VexIndex::build(vec![stmt(&id, after_purl, VexStatus::Fixed)]);

        apply(&mut e, &idx);

        assert_eq!(e.vex_suppressed_count, 1);
        assert!(e.version_jumps.is_empty());
    }

    /// Maintainer-age branch: suppression drops and counts. Kills `+=`
    /// mutants at line 101.
    #[test]
    fn apply_maintainer_age_suppresses_and_counts() {
        let mut e = Enrichment::default();
        let purl = "pkg:npm/freshpkg@0.1.0";
        e.maintainer_age = vec![MaintainerAgeFinding {
            component: comp(purl, "freshpkg", "0.1.0"),
            top_contributor: "alice".into(),
            first_commit_at: "2026-04-26T00:00:00Z".into(),
            days_old: 3,
        }];
        let id = crate::vex::synthetic_id::maintainer_age(&e.maintainer_age[0]);
        let idx = VexIndex::build(vec![stmt(&id, purl, VexStatus::NotAffected)]);

        apply(&mut e, &idx);

        assert_eq!(e.vex_suppressed_count, 1);
        assert!(e.maintainer_age.is_empty());
    }

    /// License-violation branch: suppression drops and counts. Kills `+=`
    /// mutants at line 125.
    #[test]
    fn apply_license_violations_suppresses_and_counts() {
        let mut e = Enrichment::default();
        let purl = "pkg:cargo/llvm-sys@1.0.0";
        e.license_violations = vec![LicenseViolation {
            component: comp(purl, "llvm-sys", "1.0.0"),
            license: "GPL-3.0-only".into(),
            matched_rule: "deny: GPL-3.0-only".into(),
            kind: LicenseViolationKind::Deny,
        }];
        let id = crate::vex::synthetic_id::license_violation(&e.license_violations[0]);
        let idx = VexIndex::build(vec![stmt(&id, purl, VexStatus::NotAffected)]);

        apply(&mut e, &idx);

        assert_eq!(e.vex_suppressed_count, 1);
        assert!(e.license_violations.is_empty());
    }

    /// `vex_suppressed_count` is `+=`, not `=`: pre-existing values from a
    /// prior pass are preserved. Kills the line 139 `+=` -> `=` /
    /// `-=` / `*=` mutants.
    #[test]
    fn apply_accumulates_into_existing_suppressed_count() {
        let mut e = Enrichment {
            vex_suppressed_count: 7,
            ..Default::default()
        };
        let purl = "pkg:npm/foo@1.0.0".to_string();
        e.vulns
            .insert(purl.clone(), vec![VulnRef::new("CVE-X", Severity::High)]);
        let idx = VexIndex::build(vec![stmt("CVE-X", &purl, VexStatus::NotAffected)]);

        apply(&mut e, &idx);

        // 7 (pre-existing) + 1 (new suppression) = 8. -= would give 6, *= 7.
        assert_eq!(e.vex_suppressed_count, 8);
    }
}
