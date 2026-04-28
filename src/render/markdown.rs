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

use std::fmt::Write as _;

use crate::diff::ChangeSet;
use crate::enrich::Enrichment;
use crate::enrich::typosquat::TyposquatFinding;
use crate::enrich::version_jump::VersionJumpFinding;
use crate::model::Component;

pub fn render(cs: &ChangeSet, enrichment: &Enrichment) -> String {
    let mut out = String::new();
    out.push_str("## SBOM diff\n\n");

    if cs.is_empty() && !enrichment.has_findings() {
        out.push_str("_No dependency changes._\n");
        return out;
    }

    out.push_str("| Change | Count |\n|---|---:|\n");
    let _ = writeln!(out, "| Added | {} |", cs.added.len());
    let _ = writeln!(out, "| Removed | {} |", cs.removed.len());
    let _ = writeln!(out, "| Version changed | {} |", cs.version_changed.len());
    let _ = writeln!(out, "| License changed | {} |", cs.license_changed.len());
    if !enrichment.vulns.is_empty() {
        let _ = writeln!(
            out,
            "| Vulnerabilities | {} |",
            enrichment.vulns.values().map(Vec::len).sum::<usize>()
        );
    }
    if !enrichment.typosquats.is_empty() {
        let _ = writeln!(
            out,
            "| Possible typosquats | {} |",
            enrichment.typosquats.len()
        );
    }
    if !enrichment.version_jumps.is_empty() {
        let _ = writeln!(
            out,
            "| Multi-major version jumps | {} |",
            enrichment.version_jumps.len()
        );
    }
    out.push('\n');

    if !cs.added.is_empty() {
        out.push_str("### Added\n\n");
        out.push_str("| Ecosystem | Name | Version |\n|---|---|---|\n");
        for c in &cs.added {
            let _ = writeln!(out, "| {} | {} | {} |", c.ecosystem, c.name, c.version);
        }
        out.push('\n');
    }

    if !cs.removed.is_empty() {
        out.push_str("### Removed\n\n");
        out.push_str("| Ecosystem | Name | Version |\n|---|---|---|\n");
        for c in &cs.removed {
            let _ = writeln!(out, "| {} | {} | {} |", c.ecosystem, c.name, c.version);
        }
        out.push('\n');
    }

    if !cs.version_changed.is_empty() {
        out.push_str("### Version changed\n\n");
        out.push_str("| Ecosystem | Name | Before | After |\n|---|---|---|---|\n");
        for (b, a) in &cs.version_changed {
            let _ = writeln!(
                out,
                "| {} | {} | {} | {} |",
                a.ecosystem, a.name, b.version, a.version
            );
        }
        out.push('\n');
    }

    if !cs.license_changed.is_empty() {
        out.push_str("### License changed (same version)\n\n");
        out.push_str(
            "Same version, different licenses — investigate. A re-publish under \
             different terms can indicate a corrected SBOM, a deliberate license \
             change, or a supply-chain swap. Verify the source matches.\n\n",
        );
        out.push_str("| Ecosystem | Name | Version | Before | After |\n|---|---|---|---|---|\n");
        for (b, a) in &cs.license_changed {
            let _ = writeln!(
                out,
                "| {} | {} | {} | {} | {} |",
                a.ecosystem,
                a.name,
                a.version,
                license_cell(&b.licenses),
                license_cell(&a.licenses),
            );
        }
        out.push('\n');
    }

    if !enrichment.vulns.is_empty() {
        out.push_str("### Vulnerabilities (added/upgraded deps)\n\n");
        out.push_str(
            "Advisories per OSV.dev. Click each ID for details, fixed versions, and severity.\n\n",
        );
        out.push_str("| Ecosystem | Name | Version | Advisories |\n|---|---|---|---|\n");
        write_vuln_rows(&mut out, &cs.added, enrichment);
        for (_, after) in &cs.version_changed {
            write_one_vuln_row(&mut out, after, enrichment);
        }
        out.push('\n');
    }

    if !enrichment.typosquats.is_empty() {
        out.push_str("### Possible typosquats\n\n");
        out.push_str(
            "These newly added dependencies have names similar to popular packages. \
             High similarity does not prove malicious intent — investigate the package \
             source before merging.\n\n",
        );
        out.push_str(
            "| Ecosystem | Name | Version | Similar to | Similarity |\n|---|---|---|---|---:|\n",
        );
        for f in &enrichment.typosquats {
            write_typosquat_row(&mut out, f);
        }
        out.push('\n');
    }

    if !enrichment.version_jumps.is_empty() {
        out.push_str("### Multi-major version jumps\n\n");
        out.push_str(
            "These dependencies crossed two or more major versions in a single diff. \
             Multi-major bumps can hide takeover swaps, namespace reuse, or large \
             refactors that bypass the SemVer signals reviewers usually rely on. \
             Confirm the upgrade is intentional and the source matches.\n\n",
        );
        out.push_str(
            "| Ecosystem | Name | Before | After | Major bump |\n|---|---|---|---|---:|\n",
        );
        for f in &enrichment.version_jumps {
            write_version_jump_row(&mut out, f);
        }
        out.push('\n');
    }

    out
}

fn write_version_jump_row(out: &mut String, f: &VersionJumpFinding) {
    let _ = writeln!(
        out,
        "| {} | {} | {} | {} | {} → {} |",
        f.after.ecosystem,
        f.after.name,
        f.before.version,
        f.after.version,
        f.before_major,
        f.after_major,
    );
}

fn write_typosquat_row(out: &mut String, f: &TyposquatFinding) {
    let _ = writeln!(
        out,
        "| {} | {} | {} | {} | {:.2} |",
        f.component.ecosystem, f.component.name, f.component.version, f.closest, f.score
    );
}

fn write_vuln_rows(out: &mut String, components: &[Component], enrichment: &Enrichment) {
    for c in components {
        write_one_vuln_row(out, c, enrichment);
    }
}

fn write_one_vuln_row(out: &mut String, c: &Component, enrichment: &Enrichment) {
    let ids = enrichment.vulns_for(c.purl.as_deref());
    if ids.is_empty() {
        return;
    }
    let advisories = ids
        .iter()
        .map(|id| format!("[{id}](https://osv.dev/vulnerability/{id})"))
        .collect::<Vec<_>>()
        .join(", ");
    let _ = writeln!(
        out,
        "| {} | {} | {} | {} |",
        c.ecosystem, c.name, c.version, advisories
    );
}

fn license_cell(licenses: &[String]) -> String {
    if licenses.is_empty() {
        "(none)".to_string()
    } else {
        licenses.join(", ")
    }
}

#[cfg(test)]
mod tests {
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
    fn renders_added_section() {
        let cs = ChangeSet {
            added: vec![comp("plain-crypto-js", "4.2.1", Ecosystem::Npm, None)],
            ..Default::default()
        };
        let md = render(&cs, &Enrichment::default());
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
        let md = render(&cs, &Enrichment::default());
        assert!(md.contains("### Version changed"));
        assert!(md.contains("| Ecosystem | Name | Before | After |"));
        assert!(md.contains("| npm | axios | 1.14.0 | 1.14.1 |"));
    }

    #[test]
    fn license_changed_section_includes_investigation_callout() {
        let mut before_c = comp("axios", "1.14.0", Ecosystem::Npm, None);
        before_c.licenses = vec!["MIT".to_string()];
        let mut after_c = comp("axios", "1.14.0", Ecosystem::Npm, None);
        after_c.licenses = vec!["GPL-3.0".to_string()];
        let cs = ChangeSet {
            license_changed: vec![(before_c, after_c)],
            ..Default::default()
        };
        let md = render(&cs, &Enrichment::default());
        assert!(md.contains("### License changed (same version)"));
        assert!(md.contains("investigate"));
        assert!(md.contains("supply-chain swap"));
        assert!(md.contains("| npm | axios | 1.14.0 | MIT | GPL-3.0 |"));
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
    fn empty_license_list_renders_as_none() {
        let mut before_c = comp("foo", "1.0", Ecosystem::Npm, None);
        before_c.licenses = vec![];
        let mut after_c = comp("foo", "1.0", Ecosystem::Npm, None);
        after_c.licenses = vec!["MIT".to_string()];
        let cs = ChangeSet {
            license_changed: vec![(before_c, after_c)],
            ..Default::default()
        };
        let md = render(&cs, &Enrichment::default());
        assert!(md.contains("| npm | foo | 1.0 | (none) | MIT |"));
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
            vec!["GHSA-xxxx-yyyy-zzzz".to_string()],
        );
        let md = render(&cs, &e);
        assert!(md.contains("### Vulnerabilities (added/upgraded deps)"));
        assert!(md.contains("| Vulnerabilities | 1 |"));
        assert!(
            md.contains("[GHSA-xxxx-yyyy-zzzz](https://osv.dev/vulnerability/GHSA-xxxx-yyyy-zzzz)")
        );
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
    fn typosquat_section_renders_with_similarity_table() {
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
        e.typosquats
            .push(crate::enrich::typosquat::TyposquatFinding {
                component: cs.added[0].clone(),
                closest: "crypto-js".to_string(),
                score: 0.95,
            });
        let md = render(&cs, &e);
        assert!(md.contains("### Possible typosquats"));
        assert!(md.contains("| Possible typosquats | 1 |"));
        assert!(md.contains("similar to popular packages"));
        assert!(
            !md.contains("is a typosquat"),
            "must use 'similar to' wording, not 'is a typosquat' (reputational care)"
        );
        assert!(md.contains("| npm | plain-crypto-js | 4.2.1 | crypto-js | 0.95 |"));
    }

    #[test]
    fn typosquat_section_omitted_when_no_findings() {
        let cs = ChangeSet {
            added: vec![comp("safe", "1.0", Ecosystem::Npm, None)],
            ..Default::default()
        };
        let md = render(&cs, &Enrichment::default());
        assert!(!md.contains("### Possible typosquats"));
        assert!(!md.contains("| Possible typosquats |"));
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
    fn version_jump_section_renders_with_table() {
        let before = comp("react", "16.14.0", Ecosystem::Npm, None);
        let after = comp("react", "19.0.0", Ecosystem::Npm, None);
        let cs = ChangeSet {
            version_changed: vec![(before.clone(), after.clone())],
            ..Default::default()
        };
        let mut e = Enrichment::default();
        e.version_jumps
            .push(crate::enrich::version_jump::VersionJumpFinding {
                before,
                after,
                before_major: 16,
                after_major: 19,
            });
        let md = render(&cs, &e);
        assert!(md.contains("### Multi-major version jumps"));
        assert!(md.contains("| Multi-major version jumps | 1 |"));
        assert!(md.contains("| Ecosystem | Name | Before | After | Major bump |"));
        assert!(md.contains("| npm | react | 16.14.0 | 19.0.0 | 16 → 19 |"));
        assert!(md.contains("takeover swaps"));
    }

    #[test]
    fn version_jump_section_omitted_when_no_findings() {
        let cs = ChangeSet {
            added: vec![comp("safe", "1.0", Ecosystem::Npm, None)],
            ..Default::default()
        };
        let md = render(&cs, &Enrichment::default());
        assert!(!md.contains("### Multi-major version jumps"));
        assert!(!md.contains("| Multi-major version jumps |"));
    }
}
