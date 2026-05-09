use std::fmt::Write as _;

use crate::enrich::Enrichment;
use crate::render::markdown::section;

pub fn render(enrichment: &Enrichment) -> String {
    if enrichment.recently_published.is_empty() {
        return String::new();
    }

    let mut out = String::new();
    section::open(
        &mut out,
        "Recently published (added deps)",
        enrichment.recently_published.len(),
        None,
    );
    out.push_str(
        "These newly added dependencies were published to their registry within the \
         configured threshold (default 14 days). Recent publishes correlate with \
         takeover swaps and namespace-reuse attacks. \
         [Why this matters](https://metbcy.github.io/bomdrift/enrichers/registry.html)\n\n",
    );
    out.push_str("| Ecosystem | Name | Version | Published | Days |\n|---|---|---|---|---:|\n");
    for f in &enrichment.recently_published {
        let _ = writeln!(
            out,
            "| {} | {} | {} | {} | {} |",
            f.component.ecosystem,
            f.component.name,
            f.component.version,
            f.published_at,
            f.days_old,
        );
    }
    section::close(&mut out);

    out
}
