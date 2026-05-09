use std::fmt::Write as _;

use crate::enrich::Enrichment;
use crate::enrich::version_jump::VersionJumpFinding;
use crate::render::markdown::section;

pub fn render(enrichment: &Enrichment) -> String {
    if enrichment.version_jumps.is_empty() {
        return String::new();
    }

    let mut out = String::new();
    section::open(
        &mut out,
        "Multi-major version jumps",
        enrichment.version_jumps.len(),
        None,
    );
    out.push_str(
        "These dependencies crossed two or more major versions in a single diff. \
         Multi-major bumps can hide takeover swaps, namespace reuse, or large \
         refactors that bypass the SemVer signals reviewers usually rely on. \
         Confirm the upgrade is intentional and the source matches. \
         [Why this matters](https://metbcy.github.io/bomdrift/enrichers/version-jump.html)\n\n",
    );
    out.push_str("| Ecosystem | Name | Before | After | Major bump |\n|---|---|---|---|---:|\n");
    for f in &enrichment.version_jumps {
        write_row(&mut out, f);
    }
    section::close(&mut out);

    out
}

fn write_row(out: &mut String, f: &VersionJumpFinding) {
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
    fn version_jump_section_renders_with_table() {
        let before = comp("react", "16.14.0", Ecosystem::Npm, None);
        let after = comp("react", "19.0.0", Ecosystem::Npm, None);
        let mut e = Enrichment::default();
        e.version_jumps.push(VersionJumpFinding {
            before,
            after,
            before_major: 16,
            after_major: 19,
        });
        let md = render(&e);
        assert!(md.contains("### Multi-major version jumps"));
        assert!(md.contains("| Ecosystem | Name | Before | After | Major bump |"));
        assert!(md.contains("| npm | react | 16.14.0 | 19.0.0 | 16 → 19 |"));
        assert!(md.contains("takeover swaps"));
    }

    #[test]
    fn version_jump_section_omitted_when_no_findings() {
        let md = render(&Enrichment::default());
        assert!(!md.contains("### Multi-major version jumps"));
        assert!(!md.contains("| Multi-major version jumps |"));
    }
}
