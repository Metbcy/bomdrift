//! EPSS (Exploit Prediction Scoring System) enrichment.
//!
//! EPSS publishes a per-CVE probability of exploitation in the next 30 days,
//! refreshed daily. We query <https://api.first.org/data/v1/epss?cve=...>
//! in batches and surface the score on every [`VulnRef`] whose primary id
//! or aliases include a CVE-prefixed identifier.
//!
//! Best-effort: a network failure or parse error logs to stderr at
//! `BOMDRIFT_DEBUG=1` and returns Ok with no enrichment applied. The diff
//! still renders.
//!
//! Disk cache: `<XDG_CACHE>/bomdrift/epss/<cve>.json`, 24h TTL. Mirrors
//! [`crate::enrich::cache`]'s atomicity and miss-on-corrupt semantics.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::enrich::Enrichment;
use crate::enrich::cache::CACHE_TTL_SECS;

const EPSS_API_URL: &str = "https://api.first.org/data/v1/epss";
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(15);
/// FIRST.org documents a 100-CVE batch ceiling on the `cve=` param.
const MAX_BATCH: usize = 100;
const SUBDIR: &str = "epss";
/// 24 hours — same TTL as the OSV cache so successive PR pushes within a
/// work session hit cache.

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CacheEntry {
    fetched_at: u64,
    score: Option<f32>,
}

/// Apply EPSS scores to every [`VulnRef`] in `e.vulns`. Updates in place;
/// `--no-epss` callers should skip calling this entirely. Best-effort.
pub fn enrich(e: &mut Enrichment) -> Result<()> {
    enrich_with_url(e, EPSS_API_URL, DEFAULT_TIMEOUT)
}

fn enrich_with_url(e: &mut Enrichment, base_url: &str, timeout: Duration) -> Result<()> {
    let cves = collect_cves(e);
    if cves.is_empty() {
        return Ok(());
    }
    let mut scores: HashMap<String, f32> = HashMap::new();
    let mut to_fetch: Vec<String> = Vec::new();
    let cache_root = cache_root();
    for cve in &cves {
        if let Some(root) = &cache_root
            && let Some(cached) = read_cache(root, cve)
        {
            if let Some(s) = cached {
                scores.insert(cve.clone(), s);
            }
            continue;
        }
        to_fetch.push(cve.clone());
    }

    if !to_fetch.is_empty() {
        let agent = ureq::AgentBuilder::new().timeout(timeout).build();
        for chunk in to_fetch.chunks(MAX_BATCH) {
            match fetch_batch(&agent, base_url, chunk) {
                Ok(batch) => {
                    if let Some(root) = &cache_root {
                        for cve in chunk {
                            let s = batch.get(cve).copied();
                            write_cache(root, cve, s);
                            if let Some(score) = s {
                                scores.insert(cve.clone(), score);
                            }
                        }
                    } else {
                        for (k, v) in batch {
                            scores.insert(k, v);
                        }
                    }
                }
                Err(err) => {
                    if std::env::var("BOMDRIFT_DEBUG").is_ok() {
                        eprintln!("epss: fetch failed: {err}");
                    }
                    // Best-effort: leave these CVEs unenriched.
                }
            }
        }
    }

    apply_scores(e, &scores);
    Ok(())
}

/// Collect every CVE-prefixed identifier referenced anywhere in `e.vulns`.
fn collect_cves(e: &Enrichment) -> Vec<String> {
    let mut set: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for refs in e.vulns.values() {
        for v in refs {
            for c in v.cves() {
                set.insert(c.to_string());
            }
        }
    }
    set.into_iter().collect()
}

/// Walk every `VulnRef` and set `epss_score` to the max score across its
/// CVE aliases (and primary id when CVE-keyed).
fn apply_scores(e: &mut Enrichment, scores: &HashMap<String, f32>) {
    for refs in e.vulns.values_mut() {
        for v in refs.iter_mut() {
            let mut max: Option<f32> = None;
            for c in v.cves() {
                if let Some(&s) = scores.get(c) {
                    max = Some(max.map(|m| m.max(s)).unwrap_or(s));
                }
            }
            if max.is_some() {
                v.epss_score = max;
            }
        }
    }
}

/// FIRST.org `/v1/epss` response shape (subset).
#[derive(Deserialize, Debug)]
struct EpssResponse {
    data: Vec<EpssDatum>,
}
#[derive(Deserialize, Debug)]
struct EpssDatum {
    cve: String,
    epss: String, // documented as a string in the JSON response.
}

fn fetch_batch(
    agent: &ureq::Agent,
    base_url: &str,
    cves: &[String],
) -> Result<HashMap<String, f32>> {
    let url = format!("{base_url}?cve={}", cves.join(","));
    let resp = agent
        .get(&url)
        .set(
            "user-agent",
            concat!("bomdrift/", env!("CARGO_PKG_VERSION")),
        )
        .call()?;
    let parsed: EpssResponse = resp.into_json()?;
    let mut out = HashMap::with_capacity(parsed.data.len());
    for d in parsed.data {
        if let Ok(score) = d.epss.parse::<f32>() {
            out.insert(d.cve, score);
        }
    }
    Ok(out)
}

fn cache_root() -> Option<PathBuf> {
    crate::refresh::default_cache_root()
        .ok()
        .map(|p| p.join(SUBDIR))
}

fn read_cache(root: &std::path::Path, cve: &str) -> Option<Option<f32>> {
    let path = root.join(format!("{}.json", sanitize(cve)));
    let body = std::fs::read(&path).ok()?;
    let entry: CacheEntry = serde_json::from_slice(&body).ok()?;
    let now = now_secs();
    if now.saturating_sub(entry.fetched_at) > CACHE_TTL_SECS {
        return None;
    }
    Some(entry.score)
}

fn write_cache(root: &std::path::Path, cve: &str, score: Option<f32>) {
    if std::fs::create_dir_all(root).is_err() {
        return;
    }
    let entry = CacheEntry {
        fetched_at: now_secs(),
        score,
    };
    let Ok(body) = serde_json::to_vec(&entry) else {
        return;
    };
    let target = root.join(format!("{}.json", sanitize(cve)));
    let mut tmp = target.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    if std::fs::write(&tmp, body).is_err() {
        return;
    }
    let _ = std::fs::rename(&tmp, &target);
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn sanitize(id: &str) -> String {
    id.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enrich::{Severity, VulnRef};

    #[test]
    fn parse_epss_response_extracts_cve_to_score_map() {
        let body = r#"{
            "status": "OK",
            "data": [
                {"cve": "CVE-2025-1111", "epss": "0.876", "percentile": "0.99"},
                {"cve": "CVE-2025-2222", "epss": "0.012", "percentile": "0.50"}
            ]
        }"#;
        let parsed: EpssResponse = serde_json::from_str(body).unwrap();
        let mut out = HashMap::new();
        for d in parsed.data {
            out.insert(d.cve, d.epss.parse::<f32>().unwrap());
        }
        assert!((out["CVE-2025-1111"] - 0.876).abs() < 1e-4);
        assert!((out["CVE-2025-2222"] - 0.012).abs() < 1e-4);
    }

    #[test]
    fn apply_scores_takes_max_across_aliases() {
        let mut e = Enrichment::default();
        let mut vulns: HashMap<String, Vec<VulnRef>> = HashMap::new();
        vulns.insert(
            "pkg:npm/foo@1".into(),
            vec![VulnRef {
                id: "GHSA-xxxx-yyyy-zzzz".into(),
                severity: Severity::High,
                aliases: vec!["CVE-2025-1".into(), "CVE-2025-2".into()],
                epss_score: None,
                kev: false,
            }],
        );
        e.vulns = vulns;

        let mut scores = HashMap::new();
        scores.insert("CVE-2025-1".to_string(), 0.10);
        scores.insert("CVE-2025-2".to_string(), 0.85);
        apply_scores(&mut e, &scores);
        let v = &e.vulns["pkg:npm/foo@1"][0];
        assert!((v.epss_score.unwrap() - 0.85).abs() < 1e-4);
    }

    #[test]
    fn collect_cves_dedups_across_components() {
        let mut e = Enrichment::default();
        let mut vulns: HashMap<String, Vec<VulnRef>> = HashMap::new();
        let v = VulnRef {
            id: "CVE-2025-X".into(),
            severity: Severity::High,
            aliases: vec!["CVE-2025-Y".into()],
            epss_score: None,
            kev: false,
        };
        vulns.insert("pkg:npm/a@1".into(), vec![v.clone()]);
        vulns.insert("pkg:npm/b@1".into(), vec![v]);
        e.vulns = vulns;
        let cves = collect_cves(&e);
        assert_eq!(cves, vec!["CVE-2025-X", "CVE-2025-Y"]);
    }

    #[test]
    fn cache_roundtrip() {
        let dir = std::env::temp_dir().join(format!(
            "bomdrift-epss-test-{}-{}",
            std::process::id(),
            now_secs()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        write_cache(&dir, "CVE-2025-1", Some(0.5));
        let got = read_cache(&dir, "CVE-2025-1").unwrap();
        assert_eq!(got, Some(0.5));
        // Negative caching: no-score-found CVE.
        write_cache(&dir, "CVE-2025-2", None);
        let got = read_cache(&dir, "CVE-2025-2").unwrap();
        assert_eq!(got, None);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
