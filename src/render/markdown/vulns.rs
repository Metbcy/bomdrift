use std::fmt::Write as _;

use crate::diff::ChangeSet;
use crate::enrich::{Enrichment, Severity, VulnRef};
use crate::model::Component;
use crate::render::markdown::section;

pub fn render(cs: &ChangeSet, enrichment: &Enrichment) -> String {
    if enrichment.vulns.is_empty() {
        return String::new();
    }

    let mut out = String::new();
    let count = enrichment.vulns.values().map(Vec::len).sum::<usize>();
    let teaser = teaser(cs, enrichment);
    section::open(
        &mut out,
        "Vulnerabilities (added/upgraded deps)",
        count,
        teaser.as_deref(),
    );
    out.push_str(
        "Advisories per OSV.dev. Click each ID for details. Severity is the highest \
         of GHSA's `database_specific.severity` for that advisory; advisories that \
         pre-date the GHSA tagging or weren't reachable at lookup time render as \
         `NONE` and don't trip `--fail-on critical-cve`. \
         [Why this matters](https://metbcy.github.io/bomdrift/enrichers/osv-cve.html)\n\n",
    );
    out.push_str("| Ecosystem | Name | Version | Advisories |\n|---|---|---|---|\n");
    // Component-row order: highest max-severity first, then alphabetical
    // by ecosystem+name. Per-component advisories are themselves
    // severity-sorted in `write_one_row`. The combined ordering means
    // Critical / High findings cluster at the top for reviewer skimmability.
    for c in components_sorted(cs, enrichment) {
        write_one_row(&mut out, c, enrichment);
    }
    section::close(&mut out);

    out
}

fn components_sorted<'a>(cs: &'a ChangeSet, enrichment: &Enrichment) -> Vec<&'a Component> {
    let mut comps: Vec<&Component> = Vec::new();
    for c in &cs.added {
        if !enrichment.vulns_for(c.purl.as_deref()).is_empty() {
            comps.push(c);
        }
    }
    for (_, after) in &cs.version_changed {
        if !enrichment.vulns_for(after.purl.as_deref()).is_empty() {
            comps.push(after);
        }
    }
    comps.sort_by(|a, b| {
        let sa = max_severity(enrichment, a);
        let sb = max_severity(enrichment, b);
        sb.cmp(&sa)
            .then_with(|| a.ecosystem.to_string().cmp(&b.ecosystem.to_string()))
            .then_with(|| a.name.cmp(&b.name))
    });
    comps
}

fn max_severity(enrichment: &Enrichment, c: &Component) -> Severity {
    enrichment
        .vulns_for(c.purl.as_deref())
        .iter()
        .map(|v| v.severity)
        .max()
        .unwrap_or(Severity::None)
}

fn teaser(cs: &ChangeSet, enrichment: &Enrichment) -> Option<String> {
    let comps = components_sorted(cs, enrichment);
    let top = comps.first()?;
    let refs = enrichment.vulns_for(top.purl.as_deref());
    let mut sorted: Vec<&VulnRef> = refs.iter().collect();
    sorted.sort_by(|a, b| b.severity.cmp(&a.severity).then_with(|| a.id.cmp(&b.id)));
    let head = sorted.first()?;
    Some(format!("top severity: {} ({})", head.severity, head.id))
}

fn write_one_row(out: &mut String, c: &Component, enrichment: &Enrichment) {
    let refs = enrichment.vulns_for(c.purl.as_deref());
    if refs.is_empty() {
        return;
    }

    // Sort highest-severity-first, then by advisory ID for tie-breaking. Stable
    // ordering matters because the action's PR-comment upsert keys on full-body
    // equality.
    let mut sorted: Vec<&VulnRef> = refs.iter().collect();
    sorted.sort_by(|a, b| b.severity.cmp(&a.severity).then_with(|| a.id.cmp(&b.id)));
    let advisories = sorted
        .iter()
        .map(|r| {
            let mut s = format!(
                "[{}](https://osv.dev/vulnerability/{}) `{}`",
                r.id, r.id, r.severity
            );
            if let Some(score) = r.epss_score {
                s.push_str(&format!(" · EPSS {score:.2}"));
            }
            if r.kev {
                s.push_str(" · **KEV**");
            }
            let key = format!("cve:{}:{}", c.purl.as_deref().unwrap_or(""), r.id);
            if let Some(ann) = enrichment.vex_annotations.get(&key) {
                s.push_str(&format!(" · VEX:{}", ann.status));
                if let Some(j) = &ann.justification {
                    s.push_str(&format!(" ({j})"));
                }
            }
            s
        })
        .collect::<Vec<_>>()
        .join(", ");
    let _ = writeln!(
        out,
        "| {} | {} | {} | {} |",
        c.ecosystem, c.name, c.version, advisories
    );
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::model::{Ecosystem, Relationship};

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
    fn vulnerability_section_renders_with_osv_links() {
        let cs = ChangeSet {
            added: vec![comp(
                "plain-crypto-js",
                "4.2.1",
                Ecosystem::Npm,
                Some("pkg:npm/plain-crypto-js@4.2.1"),
            )],
            ..Default::default()
        };
        let mut e = Enrichment::default();
        e.vulns.insert(
            "pkg:npm/plain-crypto-js@4.2.1".to_string(),
            vec![VulnRef {
                id: "GHSA-xxxx-yyyy-zzzz".to_string(),
                severity: Severity::Critical,
                aliases: Vec::new(),
                epss_score: None,
                kev: false,
            }],
        );
        let md = render(&cs, &e);
        assert!(md.contains("### Vulnerabilities (added/upgraded deps)"));
        assert!(
            md.contains("[GHSA-xxxx-yyyy-zzzz](https://osv.dev/vulnerability/GHSA-xxxx-yyyy-zzzz)")
        );
        assert!(md.contains("`CRITICAL`"));
    }

    #[test]
    fn vulnerability_section_sorts_advisories_by_severity_then_id() {
        let cs = ChangeSet {
            added: vec![comp(
                "vuln",
                "1.0",
                Ecosystem::Npm,
                Some("pkg:npm/vuln@1.0"),
            )],
            ..Default::default()
        };
        let mut e = Enrichment::default();
        e.vulns.insert(
            "pkg:npm/vuln@1.0".to_string(),
            vec![
                VulnRef {
                    id: "CVE-2025-medium".to_string(),
                    severity: Severity::Medium,
                    aliases: Vec::new(),
                    epss_score: None,
                    kev: false,
                },
                VulnRef {
                    id: "CVE-2025-critical".to_string(),
                    severity: Severity::Critical,
                    aliases: Vec::new(),
                    epss_score: None,
                    kev: false,
                },
                VulnRef {
                    id: "CVE-2025-high".to_string(),
                    severity: Severity::High,
                    aliases: Vec::new(),
                    epss_score: None,
                    kev: false,
                },
            ],
        );
        let md = render(&cs, &e);
        let pos_crit = md.find("CVE-2025-critical").unwrap();
        let pos_high = md.find("CVE-2025-high").unwrap();
        let pos_med = md.find("CVE-2025-medium").unwrap();
        assert!(pos_crit < pos_high && pos_high < pos_med);
    }

    #[test]
    fn vulnerability_section_omitted_when_no_findings() {
        let cs = ChangeSet {
            added: vec![comp(
                "safe",
                "1.0",
                Ecosystem::Npm,
                Some("pkg:npm/safe@1.0"),
            )],
            ..Default::default()
        };
        let md = render(&cs, &Enrichment::default());
        assert!(!md.contains("### Vulnerabilities"));
        assert!(!md.contains("| Vulnerabilities |"));
    }

    #[test]
    fn vuln_section_summary_includes_top_severity_teaser() {
        let cs = ChangeSet {
            added: vec![
                comp(
                    "low-risk",
                    "1.0",
                    Ecosystem::Npm,
                    Some("pkg:npm/low-risk@1.0"),
                ),
                comp("hot", "1.0", Ecosystem::Npm, Some("pkg:npm/hot@1.0")),
            ],
            ..Default::default()
        };
        let mut e = Enrichment::default();
        e.vulns.insert(
            "pkg:npm/low-risk@1.0".into(),
            vec![VulnRef {
                id: "GHSA-medium".into(),
                severity: Severity::Medium,
                aliases: Vec::new(),
                epss_score: None,
                kev: false,
            }],
        );
        e.vulns.insert(
            "pkg:npm/hot@1.0".into(),
            vec![VulnRef {
                id: "CVE-2025-critical".into(),
                severity: Severity::Critical,
                aliases: Vec::new(),
                epss_score: None,
                kev: false,
            }],
        );
        let md = render(&cs, &e);
        assert!(md.contains("top severity: CRITICAL (CVE-2025-critical)"));
    }

    #[test]
    fn vuln_rows_sorted_by_max_severity_across_components() {
        let cs = ChangeSet {
            added: vec![
                comp(
                    "low-risk",
                    "1.0",
                    Ecosystem::Npm,
                    Some("pkg:npm/low-risk@1.0"),
                ),
                comp("hot", "1.0", Ecosystem::Npm, Some("pkg:npm/hot@1.0")),
            ],
            ..Default::default()
        };
        let mut e = Enrichment::default();
        e.vulns.insert(
            "pkg:npm/low-risk@1.0".into(),
            vec![VulnRef {
                id: "GHSA-medium".into(),
                severity: Severity::Medium,
                aliases: Vec::new(),
                epss_score: None,
                kev: false,
            }],
        );
        e.vulns.insert(
            "pkg:npm/hot@1.0".into(),
            vec![VulnRef {
                id: "CVE-2025-critical".into(),
                severity: Severity::Critical,
                aliases: Vec::new(),
                epss_score: None,
                kev: false,
            }],
        );
        let md = render(&cs, &e);
        let pos_hot = md.find("| npm | hot |").expect("hot row present");
        let pos_low = md.find("| npm | low-risk |").expect("low-risk row present");
        assert!(pos_hot < pos_low);
    }
}
