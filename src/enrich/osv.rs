//! OSV.dev CVE enrichment for changed dependencies.
//!
//! Two-stage protocol:
//!
//! 1. **`/v1/querybatch`** — POST every purl of every component in
//!    `ChangeSet.added` and the after-side of `ChangeSet.version_changed`,
//!    chunked by [`MAX_QUERIES_PER_BATCH`]. Returns advisory IDs only.
//! 2. **`/v1/vulns/{id}`** — GET each unique advisory ID returned in step 1
//!    and parse `database_specific.severity` (GHSA's text label) to populate
//!    [`crate::enrich::Severity`].
//!
//! Stage 2 is N+1 — one HTTP roundtrip per unique advisory — but advisories
//! are deduplicated across components first, so the worst-case "200 components
//! all flagged for the same Shai-Hulud worm advisory" PR makes one /vulns
//! call, not 200. The on-disk OSV cache (separate v0.3 module) brings the
//! amortized cost back to zero on reruns.
//!
//! Both stages are best-effort: callers should surface errors as warnings
//! and continue rendering the diff. OSV being unreachable is not a reason to
//! block a PR review. A failed /vulns/{id} lookup yields
//! [`Severity::None`](crate::enrich::Severity::None) for that advisory and
//! a single stderr warning per run.

use std::collections::{BTreeSet, HashMap};
use std::time::Duration;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::diff::ChangeSet;
use crate::enrich::{Enrichment, Severity, VulnRef};

const OSV_BATCH_URL: &str = "https://api.osv.dev/v1/querybatch";
const OSV_VULN_URL_BASE: &str = "https://api.osv.dev/v1/vulns/";
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_QUERIES_PER_BATCH: usize = 1000;

pub fn enrich(cs: &ChangeSet) -> Result<Enrichment> {
    enrich_cached(cs, false)
}

/// Like [`enrich`] but lets the caller opt out of the on-disk severity cache
/// (`bomdrift diff --no-osv-cache`).
pub fn enrich_cached(cs: &ChangeSet, no_cache: bool) -> Result<Enrichment> {
    enrich_cached_with_ttl(cs, no_cache, None)
}

/// Like [`enrich_cached`] but lets the caller override the cache TTL
/// (driven by `--cache-ttl-hours`). `None` means use the default.
pub fn enrich_cached_with_ttl(
    cs: &ChangeSet,
    no_cache: bool,
    cache_ttl_hours: Option<u64>,
) -> Result<Enrichment> {
    let purls = candidate_purls(cs);
    if purls.is_empty() {
        return Ok(Enrichment::default());
    }
    let cache = crate::enrich::cache::open_unless_disabled_with_ttl(no_cache, cache_ttl_hours);
    enrich_with(
        &purls,
        OSV_BATCH_URL,
        OSV_VULN_URL_BASE,
        DEFAULT_TIMEOUT,
        cache.as_ref(),
    )
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

fn enrich_with(
    purls: &[String],
    batch_url: &str,
    vuln_url_base: &str,
    timeout: Duration,
    cache: Option<&crate::enrich::cache::Cache>,
) -> Result<Enrichment> {
    let agent = ureq::AgentBuilder::new().timeout(timeout).build();

    let mut purl_to_ids: HashMap<String, Vec<String>> = HashMap::new();
    for chunk in purls.chunks(MAX_QUERIES_PER_BATCH) {
        let response = post_batch(&agent, chunk, batch_url)?;
        merge_ids(&mut purl_to_ids, chunk, response);
    }

    // Deduplicate advisory IDs across components before /vulns/{id}
    // lookups. Worst-case 200-component-all-flagged-for-Shai-Hulud → 1 call,
    // not 200. BTreeSet ordering also means the lookups happen in a stable
    // order, which makes the warn-once-on-failure stderr output deterministic.
    let unique_ids: BTreeSet<String> = purl_to_ids.values().flatten().cloned().collect();
    let mut details: HashMap<String, (Severity, Vec<String>)> = HashMap::new();
    let mut lookup_failures = 0usize;
    let mut cache_hits = 0usize;
    for id in &unique_ids {
        if let Some(c) = cache
            && let Some((sev, aliases)) = c.get_full(id)
        {
            details.insert(id.clone(), (sev, aliases));
            cache_hits += 1;
            continue;
        }
        match fetch_detail(&agent, vuln_url_base, id) {
            Ok((sev, aliases)) => {
                if let Some(c) = cache {
                    c.put_full(id, sev, &aliases);
                }
                details.insert(id.clone(), (sev, aliases));
            }
            Err(_) => {
                lookup_failures += 1;
                details.insert(id.clone(), (Severity::None, Vec::new()));
                // Deliberately do NOT cache failures — a transient 5xx
                // shouldn't pin Severity::None for 24h.
            }
        }
    }
    if cache_hits > 0 {
        eprintln!(
            "osv: {cache_hits}/{} severities served from cache",
            unique_ids.len()
        );
    }
    if lookup_failures > 0 {
        eprintln!(
            "warning: {lookup_failures}/{} OSV /v1/vulns/{{id}} lookup(s) failed; \
             affected advisories surface with severity NONE and will not trip \
             --fail-on critical-cve",
            unique_ids.len()
        );
    }

    let mut vulns: HashMap<String, Vec<VulnRef>> = HashMap::new();
    for (purl, ids) in purl_to_ids {
        let refs: Vec<VulnRef> = ids
            .into_iter()
            .map(|id| {
                let (severity, aliases) = details
                    .get(&id)
                    .cloned()
                    .unwrap_or((Severity::None, Vec::new()));
                VulnRef {
                    id,
                    severity,
                    aliases,
                    epss_score: None,
                    kev: false,
                }
            })
            .collect();
        if !refs.is_empty() {
            vulns.insert(purl, refs);
        }
    }

    Ok(Enrichment {
        vulns,
        typosquats: Vec::new(),
        version_jumps: Vec::new(),
        maintainer_age: Vec::new(),
        license_violations: Vec::new(),
        recently_published: Vec::new(),
        deprecated: Vec::new(),
        maintainer_set_changed: Vec::new(),
        vex_annotations: std::collections::HashMap::new(),
        vex_suppressed_count: 0,
        plugin_findings: Vec::new(),
    })
}

fn post_batch(agent: &ureq::Agent, purls: &[String], url: &str) -> Result<OsvBatchResponse> {
    let body = OsvBatchRequest::from_purls(purls);
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

fn fetch_detail(
    agent: &ureq::Agent,
    vuln_url_base: &str,
    id: &str,
) -> Result<(Severity, Vec<String>)> {
    let url = format!("{vuln_url_base}{id}");
    let resp = agent
        .get(&url)
        .set(
            "user-agent",
            concat!("bomdrift/", env!("CARGO_PKG_VERSION")),
        )
        .call()
        .with_context(|| format!("OSV.dev /v1/vulns/{id} request failed"))?;
    let parsed: OsvVulnDetail = resp
        .into_json()
        .with_context(|| format!("parsing OSV detail JSON for {id}"))?;
    Ok((
        severity_from_detail(&parsed),
        aliases_from_detail(&parsed, id),
    ))
}

/// Extract sorted, deduplicated aliases from `/v1/vulns/{id}`. The primary
/// id is excluded so consumers can iterate `aliases` without re-checking
/// against the primary; sorting gives byte-deterministic JSON output.
fn aliases_from_detail(detail: &OsvVulnDetail, primary: &str) -> Vec<String> {
    let mut out: BTreeSet<String> = detail
        .aliases
        .clone()
        .unwrap_or_default()
        .into_iter()
        .collect();
    out.remove(primary);
    out.into_iter().collect()
}

/// Extract a severity bucket from the `/v1/vulns/{id}` response. Honors the
/// priority order documented on [`Severity`]: GHSA `database_specific.severity`
/// label first, then [`Severity::None`] (CVSS vector parsing is deferred to
/// v0.4 — see module doc).
fn severity_from_detail(detail: &OsvVulnDetail) -> Severity {
    if let Some(db_specific) = &detail.database_specific
        && let Some(label) = &db_specific.severity
    {
        return Severity::from_ghsa_label(label);
    }
    Severity::None
}

fn merge_ids(out: &mut HashMap<String, Vec<String>>, purls: &[String], response: OsvBatchResponse) {
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

// --- Wire-level OSV /v1/vulns/{id} shapes -----------------------------------------

#[derive(Deserialize, Debug)]
struct OsvVulnDetail {
    database_specific: Option<OsvDatabaseSpecific>,
    /// Cross-database alias IDs (e.g. CVE-… on a GHSA-keyed entry).
    aliases: Option<Vec<String>>,
}

#[derive(Deserialize, Debug)]
struct OsvDatabaseSpecific {
    /// GHSA label (`LOW|MODERATE|HIGH|CRITICAL`) when present.
    severity: Option<String>,
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
    fn merge_ids_pairs_purls_with_response_results_in_order() {
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
        merge_ids(&mut out, &purls, response);
        assert_eq!(out.len(), 1, "components with no vulns must not be in map");
        assert_eq!(out["pkg:npm/axios@1.14.1"], vec!["GHSA-xxxx"]);
    }

    #[test]
    fn merge_ids_drops_empty_vuln_lists() {
        let purls = vec!["pkg:npm/safe@1.0".to_string()];
        let response = OsvBatchResponse {
            results: vec![OsvResult {
                vulns: Some(Vec::new()),
            }],
        };
        let mut out = HashMap::new();
        merge_ids(&mut out, &purls, response);
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

    #[test]
    fn severity_from_detail_uses_database_specific_when_present() {
        let detail = OsvVulnDetail {
            database_specific: Some(OsvDatabaseSpecific {
                severity: Some("CRITICAL".to_string()),
            }),
            aliases: None,
        };
        assert_eq!(severity_from_detail(&detail), Severity::Critical);
    }

    #[test]
    fn severity_from_detail_handles_ghsa_moderate_label() {
        let detail = OsvVulnDetail {
            database_specific: Some(OsvDatabaseSpecific {
                severity: Some("MODERATE".to_string()),
            }),
            aliases: None,
        };
        assert_eq!(severity_from_detail(&detail), Severity::Medium);
    }

    #[test]
    fn severity_from_detail_returns_none_when_database_specific_absent() {
        let detail = OsvVulnDetail {
            database_specific: None,
            aliases: None,
        };
        assert_eq!(severity_from_detail(&detail), Severity::None);
    }

    #[test]
    fn severity_from_detail_returns_none_when_severity_field_missing() {
        let detail = OsvVulnDetail {
            database_specific: Some(OsvDatabaseSpecific { severity: None }),
            aliases: None,
        };
        assert_eq!(severity_from_detail(&detail), Severity::None);
    }

    #[test]
    fn aliases_from_detail_excludes_primary_and_sorts() {
        let detail = OsvVulnDetail {
            database_specific: None,
            aliases: Some(vec![
                "CVE-2025-9999".to_string(),
                "GHSA-xxxx-yyyy-zzzz".to_string(),
                "CVE-2025-1111".to_string(),
            ]),
        };
        let aliases = aliases_from_detail(&detail, "GHSA-xxxx-yyyy-zzzz");
        assert_eq!(
            aliases,
            vec!["CVE-2025-1111".to_string(), "CVE-2025-9999".to_string(),],
            "primary excluded; sorted lexicographically"
        );
    }

    #[test]
    fn aliases_from_detail_handles_missing_aliases_field() {
        let detail = OsvVulnDetail {
            database_specific: None,
            aliases: None,
        };
        assert!(aliases_from_detail(&detail, "GHSA-x").is_empty());
    }

    #[test]
    fn vulnref_cves_iterates_aliases_when_primary_is_ghsa() {
        let v = VulnRef {
            id: "GHSA-xxxx-yyyy-zzzz".to_string(),
            severity: Severity::High,
            aliases: vec!["CVE-2025-1111".to_string(), "OSV-2025-1".to_string()],
            epss_score: None,
            kev: false,
        };
        let cves: Vec<&str> = v.cves().collect();
        assert_eq!(cves, vec!["CVE-2025-1111"]);
    }

    #[test]
    fn vulnref_cves_includes_primary_when_cve_keyed() {
        let v = VulnRef {
            id: "CVE-2025-9999".to_string(),
            severity: Severity::Critical,
            aliases: vec![
                "GHSA-aaaa-bbbb-cccc".to_string(),
                "CVE-2025-1111".to_string(),
            ],
            epss_score: None,
            kev: false,
        };
        let cves: Vec<&str> = v.cves().collect();
        assert_eq!(cves, vec!["CVE-2025-9999", "CVE-2025-1111"]);
    }
}
