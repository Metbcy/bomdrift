use std::fmt::Write as _;

use crate::enrich::Enrichment;
use crate::render::markdown::section;

pub fn render(enrichment: &Enrichment) -> String {
    if enrichment.maintainer_age.is_empty() {
        return String::new();
    }

    let mut out = String::new();
    section::open(
        &mut out,
        "Young maintainers (added deps)",
        enrichment.maintainer_age.len(),
        None,
    );
    out.push_str(
        "The top contributor to each repository below opened their first commit \
         recently. The xz/liblzma backdoor (CVE-2024-3094) was authored by an \
         identity that took over maintainership after a sustained ramp-up; a \
         very-recent top contributor on a newly-introduced dependency is the \
         early signal of that pattern. Investigate the maintainer's history \
         before merging. \
         [Why this matters](https://metbcy.github.io/bomdrift/enrichers/maintainer-age.html)\n\n",
    );
    out.push_str(
        "| Ecosystem | Name | Version | Top contributor | Days since first commit |\n\
         |---|---|---|---|---:|\n",
    );
    for f in &enrichment.maintainer_age {
        let _ = writeln!(
            out,
            "| {} | {} | {} | {} | {} |",
            f.component.ecosystem,
            f.component.name,
            f.component.version,
            f.top_contributor,
            f.days_old
        );
    }
    section::close(&mut out);

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enrich::maintainer::MaintainerAgeFinding;
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

    fn maintainer_finding(name: &str, contributor: &str, days: i64) -> MaintainerAgeFinding {
        MaintainerAgeFinding {
            component: comp(name, "1.0.0", Ecosystem::Npm, None),
            top_contributor: contributor.to_string(),
            first_commit_at: "2026-04-01T00:00:00Z".to_string(),
            days_old: days,
        }
    }

    #[test]
    fn maintainer_age_section_renders_with_table_and_xz_callout() {
        let mut e = Enrichment::default();
        e.maintainer_age
            .push(maintainer_finding("liblzma-shim", "jia-tan", 14));
        let md = render(&e);
        assert!(md.contains("### Young maintainers (added deps)"));
        assert!(md.contains("xz") || md.contains("CVE-2024-3094"));
        assert!(md.contains(
            "| Ecosystem | Name | Version | Top contributor | Days since first commit |"
        ));
        assert!(md.contains("| npm | liblzma-shim | 1.0.0 | jia-tan | 14 |"));
    }

    #[test]
    fn maintainer_age_section_omitted_when_no_findings() {
        let md = render(&Enrichment::default());
        assert!(!md.contains("### Young maintainers"));
        assert!(!md.contains("| Young maintainers |"));
    }
}
