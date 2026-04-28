//! GitHub-Flavored Markdown renderer.
//!
//! Output structure:
//! - `## SBOM diff` headline (always present so the comment-tag upsert lands on a
//!   stable selector).
//! - Summary table of counts per change category.
//! - Per-category tables. Sections with zero entries are omitted entirely so the PR
//!   comment stays scannable.
//! - License-changed section is prefaced with an investigation note since same-
//!   version-different-license is the suspicious case.

use std::fmt::Write as _;

use crate::diff::ChangeSet;

pub fn render(cs: &ChangeSet) -> String {
    let mut out = String::new();
    out.push_str("## SBOM diff\n\n");

    if cs.is_empty() {
        out.push_str("_No dependency changes._\n");
        return out;
    }

    out.push_str("| Change | Count |\n|---|---:|\n");
    let _ = writeln!(out, "| Added | {} |", cs.added.len());
    let _ = writeln!(out, "| Removed | {} |", cs.removed.len());
    let _ = writeln!(out, "| Version changed | {} |", cs.version_changed.len());
    let _ = writeln!(out, "| License changed | {} |", cs.license_changed.len());
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

    out
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

    fn comp(name: &str, version: &str, eco: Ecosystem) -> Component {
        Component {
            name: name.to_string(),
            version: version.to_string(),
            ecosystem: eco,
            purl: None,
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
        let md = render(&ChangeSet::default());
        assert!(md.starts_with("## SBOM diff\n\n"));
        assert!(md.contains("_No dependency changes._"));
    }

    #[test]
    fn renders_added_section() {
        let cs = ChangeSet {
            added: vec![comp("plain-crypto-js", "4.2.1", Ecosystem::Npm)],
            ..Default::default()
        };
        let md = render(&cs);
        assert!(md.contains("### Added"));
        assert!(md.contains("| npm | plain-crypto-js | 4.2.1 |"));
    }

    #[test]
    fn renders_version_change_table_columns() {
        let before = comp("axios", "1.14.0", Ecosystem::Npm);
        let after = comp("axios", "1.14.1", Ecosystem::Npm);
        let cs = ChangeSet {
            version_changed: vec![(before, after)],
            ..Default::default()
        };
        let md = render(&cs);
        assert!(md.contains("### Version changed"));
        assert!(md.contains("| Ecosystem | Name | Before | After |"));
        assert!(md.contains("| npm | axios | 1.14.0 | 1.14.1 |"));
    }

    #[test]
    fn license_changed_section_includes_investigation_callout() {
        let mut before_c = comp("axios", "1.14.0", Ecosystem::Npm);
        before_c.licenses = vec!["MIT".to_string()];
        let mut after_c = comp("axios", "1.14.0", Ecosystem::Npm);
        after_c.licenses = vec!["GPL-3.0".to_string()];
        let cs = ChangeSet {
            license_changed: vec![(before_c, after_c)],
            ..Default::default()
        };
        let md = render(&cs);
        assert!(md.contains("### License changed (same version)"));
        assert!(md.contains("investigate"));
        assert!(md.contains("supply-chain swap"));
        assert!(md.contains("| npm | axios | 1.14.0 | MIT | GPL-3.0 |"));
    }

    #[test]
    fn empty_sections_are_omitted() {
        let cs = ChangeSet {
            added: vec![comp("foo", "1.0", Ecosystem::Npm)],
            ..Default::default()
        };
        let md = render(&cs);
        assert!(md.contains("### Added"));
        assert!(!md.contains("### Removed"));
        assert!(!md.contains("### Version changed"));
        assert!(!md.contains("### License changed"));
    }

    #[test]
    fn render_is_deterministic() {
        let cs = ChangeSet {
            added: vec![comp("a", "1.0", Ecosystem::Npm)],
            removed: vec![comp("b", "1.0", Ecosystem::Cargo)],
            ..Default::default()
        };
        assert_eq!(render(&cs), render(&cs));
    }

    #[test]
    fn empty_license_list_renders_as_none() {
        let mut before_c = comp("foo", "1.0", Ecosystem::Npm);
        before_c.licenses = vec![];
        let mut after_c = comp("foo", "1.0", Ecosystem::Npm);
        after_c.licenses = vec!["MIT".to_string()];
        let cs = ChangeSet {
            license_changed: vec![(before_c, after_c)],
            ..Default::default()
        };
        let md = render(&cs);
        assert!(md.contains("| npm | foo | 1.0 | (none) | MIT |"));
    }
}
