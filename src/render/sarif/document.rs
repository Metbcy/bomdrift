use serde_json::json;

use crate::diff::ChangeSet;
use crate::enrich::Enrichment;

use super::results::results;
use super::rules::rules;
use super::{SARIF_SCHEMA, SARIF_VERSION};

pub fn render(cs: &ChangeSet, e: &Enrichment) -> String {
    let doc = json!({
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {
                "driver": {
                    "name": "bomdrift",
                    "semanticVersion": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://metbcy.github.io/bomdrift/",
                    "rules": rules(),
                }
            },
            "results": results(cs, e),
        }]
    });
    #[allow(
        clippy::expect_used,
        reason = "invariant: serde_json::to_string_pretty cannot fail on a Value built from owned data with string keys"
    )]
    serde_json::to_string_pretty(&doc)
        .expect("invariant: serde_json::to_string_pretty cannot fail on a Value built from owned data with string keys")
}
