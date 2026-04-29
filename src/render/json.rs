//! JSON renderer. Produces a pretty-printed, machine-readable rendering of the
//! diff and enrichment graph for downstream tooling, debugging, and the future
//! SARIF renderer (which will reuse the structural shape).
//!
//! ## Shape
//!
//! ```json
//! {
//!   "changes":     <ChangeSet>,
//!   "enrichment":  <Enrichment>
//! }
//! ```
//!
//! The two namespaces are kept separate (rather than flattened) so consumers
//! can distinguish "what changed" from "what we discovered about the changes".
//! Both objects let serde derive their structure — adding new fields anywhere
//! in the diff or enrichment graph propagates to the JSON output without any
//! changes here, as long as those new fields derive `serde::Serialize`.
//!
//! New `Enrichment` fields must derive `Serialize` to appear in JSON output.
//!
//! ## Field naming
//!
//! Field names are kept in snake_case (Rust convention) rather than rewritten
//! to camelCase. Snake_case is unambiguous for tooling, requires no
//! `#[serde(rename_all)]` indirection on every type, and matches the source
//! of truth a human reading the Rust definitions would expect. The cost is
//! one extra underscore in JS/TS consumers, which is trivial.
//!
//! ## Enum representation
//!
//! Enums with an `Other(String)` escape hatch (`Ecosystem`, `HashAlg`)
//! serialize as plain strings, not tagged objects:
//! `Ecosystem::Other("library")` becomes `"library"`, matching the
//! representation of the unit variants (`Ecosystem::Npm` → `"npm"`).

use crate::diff::ChangeSet;
use crate::enrich::Enrichment;

pub fn render(cs: &ChangeSet, e: &Enrichment) -> String {
    let combined = serde_json::json!({"changes": cs, "enrichment": e});
    serde_json::to_string_pretty(&combined).expect("serialize JSON")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    use serde_json::Value;

    use crate::enrich::typosquat::TyposquatFinding;
    use crate::model::{Component, Ecosystem, Hash, HashAlg, Relationship};

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
    fn empty_diff_renders_valid_json() {
        let cs = ChangeSet::default();
        let e = Enrichment::default();
        let s = render(&cs, &e);
        let v: Value = serde_json::from_str(&s).expect("output must be valid JSON");
        assert!(v.is_object(), "top-level must be a JSON object");
        assert!(v.get("changes").is_some(), "missing `changes` key");
        assert!(v.get("enrichment").is_some(), "missing `enrichment` key");
        // Empty ChangeSet still renders all four buckets as empty arrays so
        // consumers don't have to special-case missing fields.
        let changes = v.get("changes").unwrap();
        assert!(changes.get("added").unwrap().as_array().unwrap().is_empty());
        assert!(
            changes
                .get("removed")
                .unwrap()
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert!(
            changes
                .get("version_changed")
                .unwrap()
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert!(
            changes
                .get("license_changed")
                .unwrap()
                .as_array()
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn populated_diff_round_trips() {
        let mut added = comp(
            "plain-crypto-js",
            "4.2.1",
            Ecosystem::Npm,
            Some("pkg:npm/plain-crypto-js@4.2.1"),
        );
        added.licenses = vec!["MIT".to_string()];
        added.hashes = vec![Hash {
            alg: HashAlg::Sha256,
            value: "deadbeef".to_string(),
        }];

        let removed = comp(
            "no-purl-component",
            "0.1.0",
            Ecosystem::Other("library".to_string()),
            None,
        );

        let before = comp(
            "axios",
            "1.14.0",
            Ecosystem::Npm,
            Some("pkg:npm/axios@1.14.0"),
        );
        let after = comp(
            "axios",
            "1.14.1",
            Ecosystem::Npm,
            Some("pkg:npm/axios@1.14.1"),
        );

        let cs = ChangeSet {
            added: vec![added],
            removed: vec![removed],
            version_changed: vec![(before, after)],
            license_changed: Vec::new(),
        };
        let e = Enrichment::default();

        let s = render(&cs, &e);
        let v: Value = serde_json::from_str(&s).expect("must parse back");

        let added = &v["changes"]["added"][0];
        assert_eq!(added["name"], "plain-crypto-js");
        assert_eq!(added["version"], "4.2.1");
        assert_eq!(added["ecosystem"], "npm");
        assert_eq!(added["purl"], "pkg:npm/plain-crypto-js@4.2.1");
        assert_eq!(added["licenses"][0], "MIT");
        assert_eq!(added["hashes"][0]["alg"], "sha256");
        assert_eq!(added["hashes"][0]["value"], "deadbeef");
        assert_eq!(added["relationship"], "unknown");

        let removed = &v["changes"]["removed"][0];
        assert_eq!(removed["name"], "no-purl-component");
        assert_eq!(removed["ecosystem"], "library");
        assert!(removed["purl"].is_null());

        // version_changed serializes as a JSON array of two-element pairs by default.
        let pair = &v["changes"]["version_changed"][0];
        assert!(pair.is_array(), "version-change pairs serialize as arrays");
        assert_eq!(pair[0]["version"], "1.14.0");
        assert_eq!(pair[1]["version"], "1.14.1");
    }

    #[test]
    fn enrichment_round_trips() {
        let mut vulns: HashMap<String, Vec<crate::enrich::VulnRef>> = HashMap::new();
        vulns.insert(
            "pkg:npm/axios@1.14.1".to_string(),
            vec![crate::enrich::VulnRef {
                id: "GHSA-3p68-rc4w-qgx5".to_string(),
                severity: crate::enrich::Severity::High,
            }],
        );

        let typosquats = vec![TyposquatFinding {
            component: comp(
                "plain-crypto-js",
                "4.2.1",
                Ecosystem::Npm,
                Some("pkg:npm/plain-crypto-js@4.2.1"),
            ),
            closest: "crypto-js".to_string(),
            score: 0.95,
        }];

        let e = Enrichment {
            vulns,
            typosquats,
            version_jumps: Vec::new(),
            maintainer_age: Vec::new(),
        };
        let cs = ChangeSet::default();

        let s = render(&cs, &e);
        let v: Value = serde_json::from_str(&s).expect("must parse back");

        let vulns = &v["enrichment"]["vulns"];
        assert!(vulns.is_object());
        assert_eq!(
            vulns["pkg:npm/axios@1.14.1"][0]["id"].as_str(),
            Some("GHSA-3p68-rc4w-qgx5")
        );
        assert_eq!(
            vulns["pkg:npm/axios@1.14.1"][0]["severity"].as_str(),
            Some("HIGH"),
            "severity must round-trip as the GHSA-style label"
        );

        let typo = &v["enrichment"]["typosquats"][0];
        assert_eq!(typo["component"]["name"], "plain-crypto-js");
        assert_eq!(typo["closest"], "crypto-js");
        assert!((typo["score"].as_f64().unwrap() - 0.95).abs() < 1e-9);
    }

    #[test]
    fn output_is_pretty_printed() {
        let s = render(&ChangeSet::default(), &Enrichment::default());
        assert!(
            s.contains('\n'),
            "pretty-printed output must contain newlines, got: {s}"
        );
    }

    #[test]
    fn ecosystem_other_serializes_sensibly() {
        // Ecosystem::Other("library") must serialize as the plain string
        // "library" — NOT as {"Other": "library"} — so a downstream consumer
        // can read the ecosystem field uniformly across all variants.
        let c = comp(
            "anything",
            "1.0.0",
            Ecosystem::Other("library".to_string()),
            None,
        );
        let cs = ChangeSet {
            added: vec![c],
            ..Default::default()
        };
        let s = render(&cs, &Enrichment::default());
        let v: Value = serde_json::from_str(&s).unwrap();
        assert_eq!(
            v["changes"]["added"][0]["ecosystem"], "library",
            "Other(_) variant must surface as a plain string"
        );
    }
}
