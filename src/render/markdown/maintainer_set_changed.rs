use std::fmt::Write as _;

use crate::enrich::Enrichment;
use crate::render::markdown::section;

pub fn render(enrichment: &Enrichment) -> String {
    if enrichment.maintainer_set_changed.is_empty() {
        return String::new();
    }

    let mut out = String::new();
    section::open(
        &mut out,
        "Maintainer set changed (npm)",
        enrichment.maintainer_set_changed.len(),
        None,
    );
    out.push_str(
        "These npm dependencies have a different set of maintainers compared to the \
         previous version. New publish-rights are a classic takeover-attack precursor. \
         [Why this matters](https://metbcy.github.io/bomdrift/enrichers/registry.html)\n\n",
    );
    out.push_str("| Name | Before | After | Added | Removed |\n|---|---|---|---|---|\n");
    for f in &enrichment.maintainer_set_changed {
        let _ = writeln!(
            out,
            "| {} | {} | {} | {} | {} |",
            f.after.name,
            f.before.version,
            f.after.version,
            if f.added.is_empty() {
                "(none)".to_string()
            } else {
                f.added.join(", ")
            },
            if f.removed.is_empty() {
                "(none)".to_string()
            } else {
                f.removed.join(", ")
            },
        );
    }
    section::close(&mut out);

    out
}
