use std::fmt::Write as _;

use crate::enrich::Enrichment;
use crate::render::markdown::section;

pub fn render(enrichment: &Enrichment) -> String {
    if enrichment.deprecated.is_empty() {
        return String::new();
    }

    let mut out = String::new();
    section::open(
        &mut out,
        "Deprecated upstream",
        enrichment.deprecated.len(),
        None,
    );
    out.push_str(
        "These dependencies are flagged deprecated or yanked by their package registry. \
         [Why this matters](https://metbcy.github.io/bomdrift/enrichers/registry.html)\n\n",
    );
    out.push_str("| Ecosystem | Name | Version | Message |\n|---|---|---|---|\n");
    for f in &enrichment.deprecated {
        let _ = writeln!(
            out,
            "| {} | {} | {} | {} |",
            f.component.ecosystem,
            f.component.name,
            f.component.version,
            f.message.as_deref().unwrap_or("(deprecated upstream)"),
        );
    }
    section::close(&mut out);

    out
}
