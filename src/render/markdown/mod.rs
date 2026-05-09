//! GitHub-Flavored Markdown renderer.
//!
//! Output structure:
//! - `## SBOM diff` headline (always present so the comment-tag upsert lands on a
//!   stable selector).
//! - Summary table of counts per change category, plus a "Vulnerabilities" row
//!   when OSV enrichment found any, a "Possible typosquats" row when the
//!   typosquat enricher fires, and a "Multi-major version jumps" row when the
//!   version-jump heuristic fires.
//! - Per-category tables. Sections with zero entries are omitted entirely so the
//!   PR comment stays scannable.
//! - License-changed section is prefaced with an investigation note since same-
//!   version-different-license is the suspicious case.
//! - Vulnerabilities section lists components from `added` + `version_changed`
//!   that have known advisories per OSV.dev, with hyperlinks to osv.dev.
//! - Possible typosquats section lists added components whose name resembles a
//!   popular package. Wording is "is similar to {legit}" — never "is a
//!   typosquat" — to avoid impugning the author of an innocent package.
pub mod dependency_churn;
pub mod deprecated;
pub mod footer;
pub mod license;
pub mod maintainer_age;
pub mod maintainer_set_changed;
pub mod options;
pub mod platform;
pub mod plugin;
pub mod recently_published;
pub mod section;
pub mod summary;
pub mod typosquat;
pub mod version_jump;
pub mod vulns;

pub use crate::render::markdown::options::Options;
pub use crate::render::markdown::platform::Platform;
use crate::{diff::ChangeSet, enrich::Enrichment};

pub fn render(cs: &ChangeSet, enrichment: &Enrichment) -> String {
    render_with_options(cs, enrichment, Options::default())
}

pub fn render_with_options(cs: &ChangeSet, enrichment: &Enrichment, opts: Options) -> String {
    let mut out = String::new();
    out.push_str("## SBOM diff\n\n");

    if cs.is_empty() && !enrichment.has_findings() {
        out.push_str("_No dependency changes._\n");
        return out;
    }

    out.push_str(&summary::render(cs, enrichment));

    if opts.summary_only {
        out.push_str(
            "_Per-category detail elided (`--summary-only`). The full diff is \
             available as `bomdrift diff <before> <after> --output markdown` \
             without the flag, or as the JSON / SARIF artifact attached to \
             the workflow step summary._\n",
        );
        return out;
    }

    out.push_str(&dependency_churn::render(cs, opts.findings_only));
    out.push_str(&license::render(cs, enrichment));
    out.push_str(&typosquat::render(enrichment));
    out.push_str(&vulns::render(cs, enrichment));
    out.push_str(&version_jump::render(enrichment));
    out.push_str(&maintainer_age::render(enrichment));
    out.push_str(&recently_published::render(enrichment));
    out.push_str(&deprecated::render(enrichment));
    out.push_str(&maintainer_set_changed::render(enrichment));
    out.push_str(&plugin::render(enrichment));

    out.push_str(&footer::render(opts.repo_url.as_deref(), opts.platform));

    out
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
    fn empty_changeset_says_no_changes() {
        let md = render(&ChangeSet::default(), &Enrichment::default());
        assert!(md.starts_with("## SBOM diff\n\n"));
        assert!(md.contains("_No dependency changes._"));
    }

    #[test]
    fn empty_sections_are_omitted() {
        let cs = ChangeSet {
            added: vec![comp("foo", "1.0", Ecosystem::Npm, None)],
            ..Default::default()
        };
        let md = render(&cs, &Enrichment::default());
        assert!(md.contains("### Added"));
        assert!(!md.contains("### Removed"));
        assert!(!md.contains("### Version changed"));
        assert!(!md.contains("### License changed"));
        assert!(!md.contains("### Vulnerabilities"));
    }

    #[test]
    fn render_is_deterministic() {
        let cs = ChangeSet {
            added: vec![comp("a", "1.0", Ecosystem::Npm, None)],
            removed: vec![comp("b", "1.0", Ecosystem::Cargo, None)],
            ..Default::default()
        };
        let e = Enrichment::default();
        assert_eq!(render(&cs, &e), render(&cs, &e));
    }

    #[test]
    fn summary_only_keeps_summary_table_and_drops_detail() {
        let cs = ChangeSet {
            added: vec![comp(
                "axios",
                "1.14.1",
                Ecosystem::Npm,
                Some("pkg:npm/axios@1.14.1"),
            )],
            ..Default::default()
        };
        let mut e = Enrichment::default();
        e.vulns.insert(
            "pkg:npm/axios@1.14.1".to_string(),
            vec![crate::enrich::VulnRef {
                id: "GHSA-xxxx-yyyy-zzzz".to_string(),
                severity: crate::enrich::Severity::Critical,
                aliases: Vec::new(),
                epss_score: None,
                kev: false,
            }],
        );
        let summary = render_with_options(
            &cs,
            &e,
            Options {
                summary_only: true,
                ..Default::default()
            },
        );
        // Summary table is preserved (the load-bearing part of the comment).
        assert!(summary.contains("## SBOM diff"));
        assert!(summary.contains("| Added | 1 |"));
        assert!(summary.contains("| Vulnerabilities | 1 |"));
        // Per-section detail tables are dropped.
        assert!(!summary.contains("### Added"));
        assert!(!summary.contains("### Vulnerabilities"));
        assert!(!summary.contains("GHSA-xxxx-yyyy-zzzz"));
        // Footer points the reader at the full output.
        assert!(summary.contains("--summary-only"));
    }

    #[test]
    fn summary_only_does_not_change_no_changes_short_circuit() {
        // Empty changeset still emits the "No dependency changes." line, even
        // with summary_only=true. The footer is *only* meaningful when the
        // diff was big enough to compress.
        let out = render_with_options(
            &ChangeSet::default(),
            &Enrichment::default(),
            Options {
                summary_only: true,
                ..Default::default()
            },
        );
        assert!(out.contains("_No dependency changes._"));
        assert!(!out.contains("Per-category detail elided"));
    }

    #[test]
    fn typosquat_summary_row_only_when_typosquats_present() {
        // Typosquats present but no vulns: only "Possible typosquats" row,
        // no "Vulnerabilities | 0 |" noise.
        let cs = ChangeSet {
            added: vec![comp("plain-crypto-js", "4.2.1", Ecosystem::Npm, None)],
            ..Default::default()
        };
        let mut e = Enrichment::default();
        e.typosquats
            .push(crate::enrich::typosquat::TyposquatFinding {
                component: cs.added[0].clone(),
                closest: "crypto-js".to_string(),
                score: 0.95,
            });
        let md = render(&cs, &e);
        assert!(md.contains("| Possible typosquats | 1 |"));
        assert!(!md.contains("| Vulnerabilities |"));
    }

    #[test]
    fn why_this_matters_link_appears_in_each_finding_section() {
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
            "pkg:npm/vuln@1.0".into(),
            vec![crate::enrich::VulnRef {
                id: "GHSA-x".into(),
                severity: crate::enrich::Severity::High,
                aliases: Vec::new(),
                epss_score: None,
                kev: false,
            }],
        );
        e.typosquats
            .push(crate::enrich::typosquat::TyposquatFinding {
                component: cs.added[0].clone(),
                closest: "vulnx".to_string(),
                score: 0.9,
            });
        let md = render(&cs, &e);
        // SARIF helpUri reuse — the same docs URL should appear in markdown
        // so reviewers can click through to the per-rule explanation.
        assert!(md.contains("https://metbcy.github.io/bomdrift/enrichers/osv-cve.html"));
        assert!(md.contains("https://metbcy.github.io/bomdrift/enrichers/typosquat.html"));
    }
}
