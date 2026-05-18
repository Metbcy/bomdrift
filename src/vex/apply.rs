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
