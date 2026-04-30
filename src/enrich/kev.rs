//! CISA Known Exploited Vulnerabilities (KEV) catalog enrichment.
//!
//! Single bulk feed at
//! <https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json>,
//! refreshed daily. We download the catalog once per 24h, parse the
//! `vulnerabilities[].cveID` field, and flip [`VulnRef::kev`] to true on
//! every reference whose primary id or aliases include a KEV CVE.
//!
//! Best-effort: network failure logs at `BOMDRIFT_DEBUG=1` and returns Ok
//! with no enrichment. Disk cache lives at
//! `<XDG_CACHE>/bomdrift/kev/catalog.json`.

use std::collections::HashSet;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use serde::Deserialize;

use crate::enrich::Enrichment;

const KEV_FEED_URL: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
const SUBDIR: &str = "kev";
const CACHE_FILE: &str = "catalog.json";
/// 24h — KEV publishes daily.

#[derive(Deserialize, Debug)]
struct KevFeed {
    vulnerabilities: Vec<KevEntry>,
}

#[derive(Deserialize, Debug)]
struct KevEntry {
    #[serde(rename = "cveID")]
    cve_id: String,
}

/// Apply KEV flags to every [`VulnRef`] in `e.vulns`. `--no-kev` callers
/// should skip calling this entirely.
pub fn enrich(e: &mut Enrichment) -> Result<()> {
    enrich_with_ttl(e, None)
}

/// Like [`enrich`] but lets the caller override the on-disk cache TTL
/// (driven by `--cache-ttl-hours`). `None` means use the default.
pub fn enrich_with_ttl(e: &mut Enrichment, ttl_hours: Option<u64>) -> Result<()> {
    enrich_with_url(e, KEV_FEED_URL, DEFAULT_TIMEOUT, ttl_hours)
}

fn enrich_with_url(
    e: &mut Enrichment,
    url: &str,
    timeout: Duration,
    ttl_hours: Option<u64>,
) -> Result<()> {
    if e.vulns.is_empty() {
        return Ok(());
    }
    let kev_ids = match load_or_fetch(url, timeout, ttl_hours) {
        Ok(ids) => ids,
        Err(err) => {
            if std::env::var("BOMDRIFT_DEBUG").is_ok() {
                eprintln!("kev: feed unavailable: {err}");
            }
            return Ok(());
        }
    };
    apply_kev(e, &kev_ids);
    Ok(())
}

fn apply_kev(e: &mut Enrichment, kev: &HashSet<String>) {
    for refs in e.vulns.values_mut() {
        for v in refs.iter_mut() {
            let hit = v.cves().any(|c| kev.contains(c));
            if hit {
                v.kev = true;
            }
        }
    }
}

fn load_or_fetch(url: &str, timeout: Duration, ttl_hours: Option<u64>) -> Result<HashSet<String>> {
    let cache_path = cache_path();
    let ttl = crate::enrich::cache::effective_ttl_secs(ttl_hours);
    if let Some(path) = &cache_path
        && let Some(ids) = read_cache(path, ttl)
    {
        return Ok(ids);
    }

    let agent = ureq::AgentBuilder::new().timeout(timeout).build();
    let resp = agent
        .get(url)
        .set(
            "user-agent",
            concat!("bomdrift/", env!("CARGO_PKG_VERSION")),
        )
        .call()?;
    let body = resp.into_string()?;
    let parsed: KevFeed = serde_json::from_str(&body)?;
    let ids: HashSet<String> = parsed
        .vulnerabilities
        .into_iter()
        .map(|e| e.cve_id)
        .collect();
    if let Some(path) = &cache_path {
        write_cache(path, &body);
    }
    Ok(ids)
}

fn cache_path() -> Option<PathBuf> {
    crate::refresh::default_cache_root()
        .ok()
        .map(|p| p.join(SUBDIR).join(CACHE_FILE))
}

fn read_cache(path: &std::path::Path, ttl_secs: u64) -> Option<HashSet<String>> {
    let meta = std::fs::metadata(path).ok()?;
    let modified = meta.modified().ok()?;
    let now = SystemTime::now();
    let age = now.duration_since(modified).ok()?;
    if age.as_secs() > ttl_secs {
        return None;
    }
    let body = std::fs::read(path).ok()?;
    let parsed: KevFeed = serde_json::from_slice(&body).ok()?;
    Some(
        parsed
            .vulnerabilities
            .into_iter()
            .map(|e| e.cve_id)
            .collect(),
    )
}

fn write_cache(path: &std::path::Path, body: &str) {
    if let Some(parent) = path.parent()
        && std::fs::create_dir_all(parent).is_err()
    {
        return;
    }
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    if std::fs::write(&tmp, body).is_err() {
        return;
    }
    let _ = std::fs::rename(&tmp, path);
}

#[allow(dead_code)]
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::todo,
        clippy::unimplemented
    )]
    use super::*;
    use crate::enrich::{Severity, VulnRef};
    use std::collections::HashMap;

    #[test]
    fn parse_kev_feed() {
        let body = r#"{
            "title": "CISA KEV",
            "catalogVersion": "2026.04.29",
            "vulnerabilities": [
                {"cveID": "CVE-2024-1111", "vendorProject": "Acme", "product": "X"},
                {"cveID": "CVE-2025-9999", "vendorProject": "Beta",  "product": "Y"}
            ]
        }"#;
        let parsed: KevFeed = serde_json::from_str(body).unwrap();
        let ids: HashSet<String> = parsed
            .vulnerabilities
            .into_iter()
            .map(|e| e.cve_id)
            .collect();
        assert!(ids.contains("CVE-2024-1111"));
        assert!(ids.contains("CVE-2025-9999"));
    }

    #[test]
    fn apply_kev_flips_flag_on_alias_match() {
        let mut e = Enrichment::default();
        let mut vulns: HashMap<String, Vec<VulnRef>> = HashMap::new();
        vulns.insert(
            "pkg:npm/foo@1".into(),
            vec![VulnRef {
                id: "GHSA-xxxx-yyyy-zzzz".into(),
                severity: Severity::High,
                aliases: vec!["CVE-2024-1111".into()],
                epss_score: None,
                kev: false,
            }],
        );
        e.vulns = vulns;

        let mut kev = HashSet::new();
        kev.insert("CVE-2024-1111".to_string());
        apply_kev(&mut e, &kev);
        assert!(e.vulns["pkg:npm/foo@1"][0].kev);
    }

    #[test]
    fn apply_kev_leaves_unmatched_refs_alone() {
        let mut e = Enrichment::default();
        let mut vulns: HashMap<String, Vec<VulnRef>> = HashMap::new();
        vulns.insert(
            "pkg:npm/foo@1".into(),
            vec![VulnRef {
                id: "GHSA-xxxx-yyyy-zzzz".into(),
                severity: Severity::High,
                aliases: vec!["CVE-2025-NOT-IN-KEV".into()],
                epss_score: None,
                kev: false,
            }],
        );
        e.vulns = vulns;
        apply_kev(&mut e, &HashSet::new());
        assert!(!e.vulns["pkg:npm/foo@1"][0].kev);
    }
}
