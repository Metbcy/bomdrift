use std::fmt::Write as _;

use crate::diff::ChangeSet;
use crate::render::markdown::section;

pub fn render(cs: &ChangeSet, findings_only: bool) -> String {
    let mut out = String::new();

    if findings_only {
        if has_raw_churn(cs) {
            out.push_str(
                "_Raw dependency churn detail elided (`--findings-only`); risk-bearing \
                 sections remain below._\n\n",
            );
        }
        return out;
    }

    render_added(&mut out, cs);
    render_removed(&mut out, cs);
    render_version_changed(&mut out, cs);

    out
}

fn has_raw_churn(cs: &ChangeSet) -> bool {
    !cs.added.is_empty() || !cs.removed.is_empty() || !cs.version_changed.is_empty()
}

fn render_added(out: &mut String, cs: &ChangeSet) {
    if cs.added.is_empty() {
        return;
    }

    section::open(out, "Added", cs.added.len(), None);
    out.push_str("| Ecosystem | Name | Version |\n|---|---|---|\n");
    for c in &cs.added {
        let _ = writeln!(out, "| {} | {} | {} |", c.ecosystem, c.name, c.version);
    }
    section::close(out);
}

fn render_removed(out: &mut String, cs: &ChangeSet) {
    if cs.removed.is_empty() {
        return;
    }

    section::open(out, "Removed", cs.removed.len(), None);
    out.push_str("| Ecosystem | Name | Version |\n|---|---|---|\n");
    for c in &cs.removed {
        let _ = writeln!(out, "| {} | {} | {} |", c.ecosystem, c.name, c.version);
    }
    section::close(out);
}

fn render_version_changed(out: &mut String, cs: &ChangeSet) {
    if cs.version_changed.is_empty() {
        return;
    }

    section::open(out, "Version changed", cs.version_changed.len(), None);
    out.push_str("| Ecosystem | Name | Before | After |\n|---|---|---|---|\n");
    for (b, a) in &cs.version_changed {
        let _ = writeln!(
            out,
            "| {} | {} | {} | {} |",
            a.ecosystem, a.name, b.version, a.version
        );
    }
    section::close(out);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enrich::Enrichment;
    use crate::model::{Component, Ecosystem, Relationship};
    use crate::render::markdown::{Options, render_with_options};

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
    fn renders_added_section() {
        let cs = ChangeSet {
            added: vec![comp("plain-crypto-js", "4.2.1", Ecosystem::Npm, None)],
            ..Default::default()
        };
        let md = render(&cs, false);
        assert!(md.contains("### Added"));
        assert!(md.contains("| npm | plain-crypto-js | 4.2.1 |"));
    }

    #[test]
    fn renders_version_change_table_columns() {
        let before = comp("axios", "1.14.0", Ecosystem::Npm, None);
        let after = comp("axios", "1.14.1", Ecosystem::Npm, None);
        let cs = ChangeSet {
            version_changed: vec![(before, after)],
            ..Default::default()
        };
        let md = render(&cs, false);
        assert!(md.contains("### Version changed"));
        assert!(md.contains("| Ecosystem | Name | Before | After |"));
        assert!(md.contains("| npm | axios | 1.14.0 | 1.14.1 |"));
    }

    #[test]
    fn findings_only_hides_raw_churn_but_keeps_risk_sections() {
        let cs = ChangeSet {
            added: vec![comp(
                "axios",
                "1.14.1",
                Ecosystem::Npm,
                Some("pkg:npm/axios@1.14.1"),
            )],
            version_changed: vec![(
                comp("left-pad", "1.0.0", Ecosystem::Npm, None),
                comp("left-pad", "4.0.0", Ecosystem::Npm, None),
            )],
            ..Default::default()
        };
        let mut e = Enrichment::default();
        e.vulns.insert(
            "pkg:npm/axios@1.14.1".to_string(),
            vec![crate::enrich::VulnRef {
                id: "GHSA-xxxx-yyyy-zzzz".to_string(),
                severity: crate::enrich::Severity::High,
                aliases: Vec::new(),
                epss_score: None,
                kev: false,
            }],
        );

        let md = render_with_options(
            &cs,
            &e,
            Options {
                findings_only: true,
                ..Default::default()
            },
        );

        assert!(md.contains("| Added | 1 |"));
        assert!(md.contains("| Version changed | 1 |"));
        assert!(md.contains("Raw dependency churn detail elided"));
        assert!(!md.contains("### Added"));
        assert!(!md.contains("### Version changed"));
        assert!(md.contains("### Vulnerabilities"));
        assert!(md.contains("GHSA-xxxx-yyyy-zzzz"));
    }

    #[test]
    fn sections_are_wrapped_in_collapsible_details_with_count() {
        let cs = ChangeSet {
            added: vec![comp("a", "1.0", Ecosystem::Npm, None)],
            removed: vec![comp("b", "1.0", Ecosystem::Cargo, None)],
            version_changed: vec![(
                comp("c", "1.0", Ecosystem::Npm, None),
                comp("c", "2.0", Ecosystem::Npm, None),
            )],
            ..Default::default()
        };
        let md = render(&cs, false);
        assert!(md.contains("### Added (1)\n"));
        assert!(md.contains("### Removed (1)\n"));
        assert!(md.contains("### Version changed (1)\n"));
        assert_eq!(md.matches("<details>").count(), 3);
        assert_eq!(md.matches("</summary>").count(), 3);
        assert_eq!(md.matches("</details>").count(), 3);
        assert!(md.contains("<details><summary>Show details"));
    }
}
