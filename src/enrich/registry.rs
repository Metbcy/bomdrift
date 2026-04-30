//! Registry-metadata enrichers (Phase K, v0.9).
//!
//! Three best-effort registry fetchers — npm, PyPI, crates.io — that
//! surface "recently published", "deprecated", and "maintainer set
//! changed" signals on newly added (or in npm's case, version-changed)
//! components.
//!
//! Best-effort contract: a network failure, parse error, or unknown
//! ecosystem returns Ok with no findings. Diff rendering must never
//! block on registry responses.
//!
//! Disk cache: `<XDG_CACHE>/bomdrift/registry/<eco>/<pkg>.json`, 24h
//! TTL, mirrors the OSV / EPSS cache shape.

use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::diff::ChangeSet;
use crate::model::{Component, Ecosystem};

const SUBDIR: &str = "registry";
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(15);

/// Default "recently published" age threshold (days). Components with
/// a publish timestamp younger than this trip a [`RecentlyPublished`]
/// finding. Tunable via `--recently-published-days`.
pub const MIN_PUBLISHED_AGE_DAYS: i64 = 14;

/// Newly-added component whose registry-recorded publish date is
/// younger than the configured threshold (default 14 days).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RecentlyPublished {
    pub component: Component,
    pub published_at: String,
    pub days_old: i64,
}

/// Component flagged as deprecated or yanked upstream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Deprecated {
    pub component: Component,
    pub message: Option<String>,
}

/// Maintainer set differs between two npm versions of the same package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MaintainerSetChanged {
    pub before: Component,
    pub after: Component,
    pub added: Vec<String>,
    pub removed: Vec<String>,
}

/// All registry-derived findings collected by [`enrich`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RegistryFindings {
    pub recently_published: Vec<RecentlyPublished>,
    pub deprecated: Vec<Deprecated>,
    pub maintainer_set_changed: Vec<MaintainerSetChanged>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct CacheEntry {
    fetched_at: u64,
    /// ISO 8601 publish/update timestamp (most-recent version). May
    /// be `None` when the registry didn't expose a parseable date.
    published_at: Option<String>,
    /// Per-version published_at (npm `time["<v>"]`, crates.io
    /// `versions[].published_at`). Empty when the registry doesn't
    /// expose per-version dates cleanly.
    #[serde(default)]
    versions: std::collections::HashMap<String, String>,
    deprecated_message: Option<String>,
    /// npm-only: maintainers per version.
    #[serde(default)]
    maintainers: std::collections::HashMap<String, Vec<String>>,
}

/// Run the registry enrichers. `recently_published_days` overrides
/// [`MIN_PUBLISHED_AGE_DAYS`] when `Some`. `cache_ttl_hours` overrides
/// the default 24h on-disk cache TTL when `Some`.
pub fn enrich(
    cs: &ChangeSet,
    recently_published_days: Option<i64>,
    cache_ttl_hours: Option<u64>,
) -> RegistryFindings {
    enrich_with(
        cs,
        recently_published_days,
        cache_ttl_hours,
        DEFAULT_TIMEOUT,
    )
}

fn enrich_with(
    cs: &ChangeSet,
    recently_published_days: Option<i64>,
    cache_ttl_hours: Option<u64>,
    timeout: Duration,
) -> RegistryFindings {
    let mut out = RegistryFindings::default();
    let threshold = recently_published_days.unwrap_or(MIN_PUBLISHED_AGE_DAYS);
    let ttl_secs = crate::enrich::cache::effective_ttl_secs(cache_ttl_hours);
    let agent = ureq::AgentBuilder::new().timeout(timeout).build();
    let cache_root = cache_root();

    for c in &cs.added {
        let Some(eco) = supported_ecosystem(c) else {
            continue;
        };
        let Some(entry) = lookup(&agent, cache_root.as_ref(), eco, &c.name, ttl_secs) else {
            continue;
        };
        // Recently-published check: prefer per-version date if known,
        // otherwise the top-level published_at.
        let date = entry
            .versions
            .get(&c.version)
            .cloned()
            .or_else(|| entry.published_at.clone());
        if let Some(d) = date.as_deref()
            && let Some(days) = days_since(d)
            && days < threshold
        {
            out.recently_published.push(RecentlyPublished {
                component: c.clone(),
                published_at: d.to_string(),
                days_old: days,
            });
        }
        if let Some(msg) = entry.deprecated_message.clone() {
            out.deprecated.push(Deprecated {
                component: c.clone(),
                message: Some(msg),
            });
        }
    }

    // Maintainer-set-changed (npm only).
    for (before, after) in &cs.version_changed {
        let Some(RegEco::Npm) = supported_ecosystem(after) else {
            continue;
        };
        let Some(entry) = lookup(
            &agent,
            cache_root.as_ref(),
            RegEco::Npm,
            &after.name,
            ttl_secs,
        ) else {
            continue;
        };
        let bef = entry
            .maintainers
            .get(&before.version)
            .cloned()
            .unwrap_or_default();
        let aft = entry
            .maintainers
            .get(&after.version)
            .cloned()
            .unwrap_or_default();
        if bef.is_empty() && aft.is_empty() {
            continue;
        }
        let bset: std::collections::BTreeSet<&String> = bef.iter().collect();
        let aset: std::collections::BTreeSet<&String> = aft.iter().collect();
        if bset == aset {
            continue;
        }
        let added: Vec<String> = aset.difference(&bset).map(|s| (*s).clone()).collect();
        let removed: Vec<String> = bset.difference(&aset).map(|s| (*s).clone()).collect();
        out.maintainer_set_changed.push(MaintainerSetChanged {
            before: before.clone(),
            after: after.clone(),
            added,
            removed,
        });
    }

    out
}

/// Internal eco discriminator — Copy-able because we route on it
/// repeatedly. Only the three registry-supported ecosystems are
/// represented; everything else returns `None` from
/// [`supported_ecosystem`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RegEco {
    Npm,
    PyPI,
    Cargo,
}

impl RegEco {
    fn dir(self) -> &'static str {
        match self {
            RegEco::Npm => "npm",
            RegEco::PyPI => "pypi",
            RegEco::Cargo => "cargo",
        }
    }
}

fn supported_ecosystem(c: &Component) -> Option<RegEco> {
    match c.ecosystem {
        Ecosystem::Npm => Some(RegEco::Npm),
        Ecosystem::PyPI => Some(RegEco::PyPI),
        Ecosystem::Cargo => Some(RegEco::Cargo),
        _ => None,
    }
}

fn lookup(
    agent: &ureq::Agent,
    cache_root: Option<&PathBuf>,
    eco: RegEco,
    name: &str,
    ttl_secs: u64,
) -> Option<CacheEntry> {
    if let Some(root) = cache_root
        && let Some(cached) = read_cache(root, eco, name, ttl_secs)
    {
        return Some(cached);
    }
    let entry = match eco {
        RegEco::Npm => fetch_npm(agent, name),
        RegEco::PyPI => fetch_pypi(agent, name),
        RegEco::Cargo => fetch_cargo(agent, name),
    };
    if let (Some(root), Some(e)) = (cache_root, entry.as_ref()) {
        write_cache(root, eco, name, e);
    }
    entry
}
fn fetch_npm(agent: &ureq::Agent, name: &str) -> Option<CacheEntry> {
    let url = format!("https://registry.npmjs.org/{}", url_encode(name));
    let resp = agent
        .get(&url)
        .set(
            "user-agent",
            concat!("bomdrift/", env!("CARGO_PKG_VERSION")),
        )
        .call()
        .ok()?;
    let json: serde_json::Value = resp.into_json().ok()?;
    let mut entry = CacheEntry {
        fetched_at: now_secs(),
        ..Default::default()
    };
    if let Some(t) = json.get("time").and_then(|v| v.as_object()) {
        entry.published_at = t
            .get("modified")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        for (k, v) in t {
            if k == "modified" || k == "created" {
                continue;
            }
            if let Some(s) = v.as_str() {
                entry.versions.insert(k.clone(), s.to_string());
            }
        }
    }
    if let Some(versions) = json.get("versions").and_then(|v| v.as_object()) {
        // Use the latest version's deprecated message if any version is
        // deprecated. npm sets this per-version.
        for v in versions.values() {
            if let Some(d) = v.get("deprecated").and_then(|d| d.as_str()) {
                entry.deprecated_message = Some(d.to_string());
            }
            // Per-version maintainers.
            if let Some(version) = v.get("version").and_then(|x| x.as_str())
                && let Some(maints) = v.get("maintainers").and_then(|m| m.as_array())
            {
                let mut names: Vec<String> = maints
                    .iter()
                    .filter_map(|m| m.get("name").and_then(|n| n.as_str()).map(str::to_string))
                    .collect();
                names.sort();
                names.dedup();
                entry.maintainers.insert(version.to_string(), names);
            }
        }
    }
    Some(entry)
}

fn fetch_pypi(agent: &ureq::Agent, name: &str) -> Option<CacheEntry> {
    let url = format!("https://pypi.org/pypi/{}/json", url_encode(name));
    let resp = agent
        .get(&url)
        .set(
            "user-agent",
            concat!("bomdrift/", env!("CARGO_PKG_VERSION")),
        )
        .call()
        .ok()?;
    let json: serde_json::Value = resp.into_json().ok()?;
    let mut entry = CacheEntry {
        fetched_at: now_secs(),
        ..Default::default()
    };
    let info = json.get("info");
    if let Some(yanked) = info.and_then(|i| i.get("yanked")).and_then(|v| v.as_bool())
        && yanked
    {
        let reason = info
            .and_then(|i| i.get("yanked_reason"))
            .and_then(|v| v.as_str())
            .unwrap_or("yanked");
        entry.deprecated_message = Some(format!("PyPI yanked: {reason}"));
    }
    if let Some(classifiers) = info
        .and_then(|i| i.get("classifiers"))
        .and_then(|v| v.as_array())
    {
        for c in classifiers {
            if let Some(s) = c.as_str()
                && (s.contains("Inactive") || s.contains("Abandoned"))
            {
                entry
                    .deprecated_message
                    .get_or_insert_with(|| format!("PyPI classifier: {s}"));
            }
        }
    }
    if let Some(releases) = json.get("releases").and_then(|v| v.as_object()) {
        for (ver, files) in releases {
            if let Some(arr) = files.as_array()
                && let Some(first) = arr.first()
                && let Some(s) = first.get("upload_time_iso_8601").and_then(|v| v.as_str())
            {
                entry.versions.insert(ver.clone(), s.to_string());
            }
        }
    }
    Some(entry)
}

fn fetch_cargo(agent: &ureq::Agent, name: &str) -> Option<CacheEntry> {
    let url = format!("https://crates.io/api/v1/crates/{}", url_encode(name));
    let resp = agent
        .get(&url)
        .set(
            "user-agent",
            "bomdrift/0.9.0 (https://github.com/Metbcy/bomdrift)",
        )
        .call()
        .ok()?;
    let json: serde_json::Value = resp.into_json().ok()?;
    let mut entry = CacheEntry {
        fetched_at: now_secs(),
        ..Default::default()
    };
    entry.published_at = json
        .get("crate")
        .and_then(|c| c.get("updated_at"))
        .and_then(|v| v.as_str())
        .map(str::to_string);
    if let Some(versions) = json.get("versions").and_then(|v| v.as_array()) {
        for v in versions {
            let Some(num) = v.get("num").and_then(|n| n.as_str()) else {
                continue;
            };
            if let Some(p) = v.get("published_at").and_then(|x| x.as_str()) {
                entry.versions.insert(num.to_string(), p.to_string());
            }
            if v.get("yanked").and_then(|y| y.as_bool()).unwrap_or(false) {
                entry.deprecated_message = Some(format!("crates.io yanked: version {num} yanked"));
            }
        }
    }
    Some(entry)
}

// --- cache I/O ---

fn cache_root() -> Option<PathBuf> {
    crate::refresh::default_cache_root()
        .ok()
        .map(|r| r.join(SUBDIR))
}

fn cache_path(root: &std::path::Path, eco: RegEco, name: &str) -> PathBuf {
    root.join(eco.dir())
        .join(format!("{}.json", sanitize(name)))
}

fn read_cache(
    root: &std::path::Path,
    eco: RegEco,
    name: &str,
    ttl_secs: u64,
) -> Option<CacheEntry> {
    let p = cache_path(root, eco, name);
    let body = std::fs::read(&p).ok()?;
    let entry: CacheEntry = serde_json::from_slice(&body).ok()?;
    if now_secs().saturating_sub(entry.fetched_at) > ttl_secs {
        return None;
    }
    Some(entry)
}

fn write_cache(root: &std::path::Path, eco: RegEco, name: &str, entry: &CacheEntry) {
    let p = cache_path(root, eco, name);
    if let Some(parent) = p.parent()
        && std::fs::create_dir_all(parent).is_err()
    {
        return;
    }
    let Ok(body) = serde_json::to_vec(entry) else {
        return;
    };
    let mut tmp = p.clone();
    tmp.set_extension("json.tmp");
    if std::fs::write(&tmp, body).is_err() {
        return;
    }
    let _ = std::fs::rename(&tmp, &p);
}

fn sanitize(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn url_encode(s: &str) -> String {
    // Minimal encoder for `@scope/name` and the like.
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '/' => out.push_str("%2F"),
            '@' => out.push_str("%40"),
            ' ' => out.push_str("%20"),
            _ => out.push(c),
        }
    }
    out
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn days_since(iso8601: &str) -> Option<i64> {
    use time::OffsetDateTime;
    use time::format_description::well_known::Rfc3339;
    // PyPI / npm / crates.io all emit RFC 3339 timestamps.
    let t = OffsetDateTime::parse(iso8601, &Rfc3339).ok()?;
    let now = crate::clock::now();
    Some((now - t).whole_days())
}

// --- parsers exposed for tests (skip network) ---

#[cfg(test)]
fn parse_npm_value(json: &serde_json::Value) -> CacheEntry {
    let mut entry = CacheEntry {
        fetched_at: 0,
        ..Default::default()
    };
    if let Some(t) = json.get("time").and_then(|v| v.as_object()) {
        entry.published_at = t
            .get("modified")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        for (k, v) in t {
            if k == "modified" || k == "created" {
                continue;
            }
            if let Some(s) = v.as_str() {
                entry.versions.insert(k.clone(), s.to_string());
            }
        }
    }
    if let Some(versions) = json.get("versions").and_then(|v| v.as_object()) {
        for v in versions.values() {
            if let Some(d) = v.get("deprecated").and_then(|d| d.as_str()) {
                entry.deprecated_message = Some(d.to_string());
            }
            if let Some(version) = v.get("version").and_then(|x| x.as_str())
                && let Some(maints) = v.get("maintainers").and_then(|m| m.as_array())
            {
                let mut names: Vec<String> = maints
                    .iter()
                    .filter_map(|m| m.get("name").and_then(|n| n.as_str()).map(str::to_string))
                    .collect();
                names.sort();
                names.dedup();
                entry.maintainers.insert(version.to_string(), names);
            }
        }
    }
    entry
}

#[cfg(test)]
fn parse_pypi_value(json: &serde_json::Value) -> CacheEntry {
    let mut entry = CacheEntry {
        fetched_at: 0,
        ..Default::default()
    };
    let info = json.get("info");
    if let Some(yanked) = info.and_then(|i| i.get("yanked")).and_then(|v| v.as_bool())
        && yanked
    {
        let reason = info
            .and_then(|i| i.get("yanked_reason"))
            .and_then(|v| v.as_str())
            .unwrap_or("yanked");
        entry.deprecated_message = Some(format!("PyPI yanked: {reason}"));
    }
    if let Some(classifiers) = info
        .and_then(|i| i.get("classifiers"))
        .and_then(|v| v.as_array())
    {
        for c in classifiers {
            if let Some(s) = c.as_str()
                && (s.contains("Inactive") || s.contains("Abandoned"))
            {
                entry
                    .deprecated_message
                    .get_or_insert_with(|| format!("PyPI classifier: {s}"));
            }
        }
    }
    if let Some(releases) = json.get("releases").and_then(|v| v.as_object()) {
        for (ver, files) in releases {
            if let Some(arr) = files.as_array()
                && let Some(first) = arr.first()
                && let Some(s) = first.get("upload_time_iso_8601").and_then(|v| v.as_str())
            {
                entry.versions.insert(ver.clone(), s.to_string());
            }
        }
    }
    entry
}

#[cfg(test)]
fn parse_cargo_value(json: &serde_json::Value) -> CacheEntry {
    let mut entry = CacheEntry {
        fetched_at: 0,
        ..Default::default()
    };
    entry.published_at = json
        .get("crate")
        .and_then(|c| c.get("updated_at"))
        .and_then(|v| v.as_str())
        .map(str::to_string);
    if let Some(versions) = json.get("versions").and_then(|v| v.as_array()) {
        for v in versions {
            let Some(num) = v.get("num").and_then(|n| n.as_str()) else {
                continue;
            };
            if let Some(p) = v.get("published_at").and_then(|x| x.as_str()) {
                entry.versions.insert(num.to_string(), p.to_string());
            }
            if v.get("yanked").and_then(|y| y.as_bool()).unwrap_or(false) {
                entry.deprecated_message = Some(format!("crates.io yanked: version {num} yanked"));
            }
        }
    }
    entry
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
    use serde_json::json;

    #[test]
    fn npm_parse_recent_publish_and_deprecated() {
        let v = json!({
            "time": {
                "modified": "2026-04-29T00:00:00.000Z",
                "1.0.0": "2024-01-01T00:00:00.000Z",
                "2.0.0": "2026-04-29T00:00:00.000Z"
            },
            "versions": {
                "1.0.0": {
                    "version": "1.0.0",
                    "maintainers": [{"name": "alice"}, {"name": "bob"}]
                },
                "2.0.0": {
                    "version": "2.0.0",
                    "deprecated": "use newer-pkg instead",
                    "maintainers": [{"name": "alice"}, {"name": "carol"}]
                }
            }
        });
        let e = parse_npm_value(&v);
        assert_eq!(
            e.versions.get("2.0.0").map(|s| s.as_str()),
            Some("2026-04-29T00:00:00.000Z")
        );
        assert_eq!(
            e.deprecated_message.as_deref(),
            Some("use newer-pkg instead")
        );
        assert_eq!(
            e.maintainers.get("1.0.0").unwrap(),
            &vec!["alice".to_string(), "bob".to_string()]
        );
        assert_eq!(
            e.maintainers.get("2.0.0").unwrap(),
            &vec!["alice".to_string(), "carol".to_string()]
        );
    }

    #[test]
    fn pypi_parse_yanked() {
        let v = json!({
            "info": {
                "yanked": true,
                "yanked_reason": "security",
                "classifiers": ["Development Status :: 7 - Inactive"]
            },
            "releases": {
                "1.0.0": [{"upload_time_iso_8601": "2024-01-01T00:00:00Z"}]
            }
        });
        let e = parse_pypi_value(&v);
        assert!(e.deprecated_message.as_deref().unwrap().contains("yanked"));
        assert_eq!(
            e.versions.get("1.0.0").map(|s| s.as_str()),
            Some("2024-01-01T00:00:00Z")
        );
    }

    #[test]
    fn cargo_parse_yanked_and_recent() {
        let v = json!({
            "crate": { "updated_at": "2026-04-29T00:00:00+00:00" },
            "versions": [
                { "num": "1.0.0", "yanked": false, "published_at": "2024-01-01T00:00:00+00:00" },
                { "num": "2.0.0", "yanked": true, "published_at": "2026-04-29T00:00:00+00:00" }
            ]
        });
        let e = parse_cargo_value(&v);
        assert_eq!(e.published_at.as_deref(), Some("2026-04-29T00:00:00+00:00"));
        assert!(e.deprecated_message.as_deref().unwrap().contains("yanked"));
        assert_eq!(e.versions.len(), 2);
    }

    #[test]
    fn url_encode_handles_npm_scopes() {
        assert_eq!(url_encode("@scope/name"), "%40scope%2Fname");
        assert_eq!(url_encode("plain"), "plain");
    }

    #[test]
    fn days_since_zero_for_now() {
        let _lock = crate::clock::test_env_lock();
        // SAFETY: serialized by the env_lock guard above.
        unsafe {
            std::env::set_var("SOURCE_DATE_EPOCH", "1777593600");
        }
        let d = days_since("2026-05-01T00:00:00Z").unwrap();
        assert_eq!(d, 0);
        // SAFETY: serialized by the env_lock guard above.
        unsafe {
            std::env::remove_var("SOURCE_DATE_EPOCH");
        }
    }
}
