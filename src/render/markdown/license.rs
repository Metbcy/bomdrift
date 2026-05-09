use crate::{diff::ChangeSet, enrich::Enrichment, render::markdown::section};
use std::fmt::Write;

pub fn render(cs: &ChangeSet, enrichment: &Enrichment) -> String {
    let mut out = String::new();

    render_violations(&mut out, enrichment);
    render_changed(&mut out, cs);

    out
}

fn render_violations(out: &mut String, enrichment: &Enrichment) {
    if enrichment.license_violations.is_empty() {
        return;
    }

    section::open(
        out,
        "License violations",
        enrichment.license_violations.len(),
        None,
    );
    out.push_str(
        "One or more changed components have a license that the configured \
             policy disallows. Review the matched rule and either update the \
             component, exempt it via an explicit baseline entry, or relax the \
             policy. \
             [Why this matters](https://metbcy.github.io/bomdrift/license-policy.html)\n\n",
    );
    out.push_str("| Ecosystem | Name | Version | License | Rule |\n|---|---|---|---|---|\n");
    for v in &enrichment.license_violations {
        let _ = writeln!(
            out,
            "| {} | {} | {} | `{}` | {} |",
            v.component.ecosystem, v.component.name, v.component.version, v.license, v.matched_rule,
        );
    }
    section::close(out);
}

fn render_changed(out: &mut String, cs: &ChangeSet) {
    if cs.license_changed.is_empty() {
        return;
    }

    section::open(
        out,
        "License changed (same version)",
        cs.license_changed.len(),
        None,
    );
    out.push_str(
        "Same version, different licenses — investigate. A re-publish under \
         different terms can indicate a corrected SBOM, a deliberate license \
         change, or a supply-chain swap. Verify the source matches. \
         [Why this matters](https://metbcy.github.io/bomdrift/output-formats.html#sarif-v210)\n\n",
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
    section::close(out);
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
}
