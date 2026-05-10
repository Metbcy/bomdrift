use crate::enrich::Enrichment;
use crate::render::markdown::section;
use std::fmt::Write;

pub fn render(enrichment: &Enrichment) -> String {
    if enrichment.typosquats.is_empty() {
        return String::new();
    }

    let mut out = String::new();

    let teaser = teaser(enrichment);
    section::open(
        &mut out,
        "Possible typosquats",
        enrichment.typosquats.len(),
        teaser.as_deref(),
    );
    out.push_str(
        "These newly added dependencies have names similar to popular packages. \
           High similarity does not prove malicious intent — investigate the package \
           source before merging. \
           [Why this matters](https://metbcy.github.io/bomdrift/enrichers/typosquat.html)\n\n",
    );
    out.push_str(
        "| Ecosystem | Name | Version | Similar to | Similarity |\n|---|---|---|---|---:|\n",
    );
    for f in &enrichment.typosquats {
        let _ = writeln!(
            out,
            "| {} | {} | {} | {} | {:.2} |",
            f.component.ecosystem, f.component.name, f.component.version, f.closest, f.score
        );
    }
    section::close(&mut out);

    out
}

fn teaser(enrichment: &Enrichment) -> Option<String> {
    let top = enrichment.typosquats.iter().max_by(|a, b| {
        a.score
            .partial_cmp(&b.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    })?;
    Some(format!(
        "top similarity: {:.2} ({} → {})",
        top.score, top.component.name, top.closest
    ))
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
    fn typosquat_section_renders_with_similarity_table() {
        let component = comp(
            "plain-crypto-js",
            "4.2.1",
            Ecosystem::Npm,
            Some("pkg:npm/plain-crypto-js@4.2.1"),
        );
        let mut e = Enrichment::default();
        e.typosquats
            .push(crate::enrich::typosquat::TyposquatFinding {
                component,
                closest: "crypto-js".to_string(),
                score: 0.95,
            });
        let md = render(&e);
        assert!(md.contains("### Possible typosquats"));
        assert!(md.contains("similar to popular packages"));
        assert!(!md.contains("is a typosquat"));
        assert!(md.contains("| npm | plain-crypto-js | 4.2.1 | crypto-js | 0.95 |"));
    }

    #[test]
    fn typosquat_section_omitted_when_no_findings() {
        let md = render(&Enrichment::default());
        assert!(!md.contains("### Possible typosquats"));
        assert!(!md.contains("| Possible typosquats |"));
    }

    #[test]
    fn typosquat_section_summary_includes_top_similarity_teaser() {
        let mut e = Enrichment::default();
        e.typosquats
            .push(crate::enrich::typosquat::TyposquatFinding {
                component: comp("plain-crypto-js", "4.2.1", Ecosystem::Npm, None),
                closest: "crypto-js".to_string(),
                score: 0.95,
            });
        e.typosquats
            .push(crate::enrich::typosquat::TyposquatFinding {
                component: comp("axiosx", "1.0.0", Ecosystem::Npm, None),
                closest: "axios".to_string(),
                score: 0.85,
            });
        let md = render(&e);
        assert!(md.contains("top similarity: 0.95 (plain-crypto-js → crypto-js)"));
    }
}
