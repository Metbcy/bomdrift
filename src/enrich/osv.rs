//! OSV.dev batch CVE enrichment for changed dependencies.
//!
//! Queries `https://api.osv.dev/v1/querybatch` with the purls of every component
//! in `ChangeSet.added` and the after-side of `ChangeSet.version_changed`. The
//! `/querybatch` endpoint accepts up to 1000 queries per request (we chunk if
//! larger) and returns advisory IDs only — severity/summary lookups are deferred
//! to a follow-up PR (one HTTP roundtrip is enough to flag "this changed dep is
//! known-bad" in a PR comment).
//!
//! Network errors are treated as best-effort: callers should surface them as
//! warnings and continue rendering the diff. OSV being unreachable is not a
//! reason to block a PR review.

use std::collections::HashMap;
use std::time::Duration;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::diff::ChangeSet;
use crate::enrich::Enrichment;

const OSV_BATCH_URL: &str = "https://api.osv.dev/v1/querybatch";
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_QUERIES_PER_BATCH: usize = 1000;

pub fn enrich(cs: &ChangeSet) -> Result<Enrichment> {
    let purls = candidate_purls(cs);
    if purls.is_empty() {
        return Ok(Enrichment::default());
    }
    enrich_with(&purls, OSV_BATCH_URL, DEFAULT_TIMEOUT)
}

/// Components worth querying: every purl-bearing entry in `added` and the after
/// side of `version_changed`. License-only changes are same-version and unlikely
/// to surface new advisories beyond what an earlier diff already saw.
fn candidate_purls(cs: &ChangeSet) -> Vec<String> {
    let mut out = Vec::new();
    for c in &cs.added {
        if let Some(p) = &c.purl {
            out.push(p.clone());
        }
    }
    for (_, after) in &cs.version_changed {
        if let Some(p) = &after.purl {
            out.push(p.clone());
        }
    }
    out
}

fn enrich_with(purls: &[String], url: &str, timeout: Duration) -> Result<Enrichment> {
    let mut vulns: HashMap<String, Vec<String>> = HashMap::new();
    for chunk in purls.chunks(MAX_QUERIES_PER_BATCH) {
        let response = post_batch(chunk, url, timeout)?;
        merge(&mut vulns, chunk, response);
    }
    Ok(Enrichment {
        vulns,
        typosquats: Vec::new(),
        version_jumps: Vec::new(),
        maintainer_age: Vec::new(),
    })
}

fn post_batch(purls: &[String], url: &str, timeout: Duration) -> Result<OsvBatchResponse> {
    let body = OsvBatchRequest::from_purls(purls);
    let agent = ureq::AgentBuilder::new().timeout(timeout).build();
    let body_value = serde_json::to_value(&body).context("serializing OSV request body")?;
    let resp = agent
        .post(url)
        .set(
            "user-agent",
            concat!("bomdrift/", env!("CARGO_PKG_VERSION")),
        )
        .send_json(body_value)
        .context("OSV.dev /v1/querybatch request failed")?;
    let parsed: OsvBatchResponse = resp.into_json().context("parsing OSV response JSON")?;
    Ok(parsed)
}

fn merge(out: &mut HashMap<String, Vec<String>>, purls: &[String], response: OsvBatchResponse) {
    for (purl, result) in purls.iter().zip(response.results.iter()) {
        let ids: Vec<String> = result
            .vulns
            .as_ref()
            .map(|vs| vs.iter().map(|v| v.id.clone()).collect())
            .unwrap_or_default();
        if !ids.is_empty() {
            out.insert(purl.clone(), ids);
        }
    }
}

// --- Wire-level OSV /v1/querybatch shapes ------------------------------------------

#[derive(Serialize)]
struct OsvBatchRequest {
    queries: Vec<OsvQuery>,
}

impl OsvBatchRequest {
    fn from_purls(purls: &[String]) -> Self {
        Self {
            queries: purls
                .iter()
                .map(|p| OsvQuery {
                    package: OsvPackage { purl: p.clone() },
                })
                .collect(),
        }
    }
}

#[derive(Serialize)]
struct OsvQuery {
    package: OsvPackage,
}

#[derive(Serialize)]
struct OsvPackage {
    purl: String,
}

#[derive(Deserialize, Debug)]
struct OsvBatchResponse {
    results: Vec<OsvResult>,
}

#[derive(Deserialize, Debug)]
struct OsvResult {
    vulns: Option<Vec<OsvVulnRef>>,
}

#[derive(Deserialize, Debug)]
struct OsvVulnRef {
    id: String,
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
    fn candidate_purls_extracts_from_added_and_version_changed_after() {
        let cs = ChangeSet {
            added: vec![comp("foo", "1.0", Ecosystem::Npm, Some("pkg:npm/foo@1.0"))],
            version_changed: vec![(
                comp("bar", "1.0", Ecosystem::Npm, Some("pkg:npm/bar@1.0")),
                comp("bar", "2.0", Ecosystem::Npm, Some("pkg:npm/bar@2.0")),
            )],
            ..Default::default()
        };
        let purls = candidate_purls(&cs);
        assert_eq!(
            purls,
            vec!["pkg:npm/foo@1.0".to_string(), "pkg:npm/bar@2.0".to_string()]
        );
    }

    #[test]
    fn candidate_purls_skips_components_without_purl() {
        let cs = ChangeSet {
            added: vec![comp("foo", "1.0", Ecosystem::Npm, None)],
            ..Default::default()
        };
        assert!(candidate_purls(&cs).is_empty());
    }

    #[test]
    fn merge_pairs_purls_with_response_results_in_order() {
        let purls = vec![
            "pkg:npm/axios@1.14.1".to_string(),
            "pkg:npm/safe@1.0".to_string(),
        ];
        let response = OsvBatchResponse {
            results: vec![
                OsvResult {
                    vulns: Some(vec![OsvVulnRef {
                        id: "GHSA-xxxx".to_string(),
                    }]),
                },
                OsvResult { vulns: None },
            ],
        };
        let mut out = HashMap::new();
        merge(&mut out, &purls, response);
        assert_eq!(out.len(), 1, "components with no vulns must not be in map");
        assert_eq!(out["pkg:npm/axios@1.14.1"], vec!["GHSA-xxxx"]);
    }

    #[test]
    fn merge_drops_empty_vuln_lists() {
        let purls = vec!["pkg:npm/safe@1.0".to_string()];
        let response = OsvBatchResponse {
            results: vec![OsvResult {
                vulns: Some(Vec::new()),
            }],
        };
        let mut out = HashMap::new();
        merge(&mut out, &purls, response);
        assert!(out.is_empty());
    }

    #[test]
    fn request_body_matches_osv_querybatch_schema() {
        let req = OsvBatchRequest::from_purls(&["pkg:npm/axios@1.14.1".to_string()]);
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "queries": [
                    {"package": {"purl": "pkg:npm/axios@1.14.1"}}
                ]
            })
        );
    }
}
