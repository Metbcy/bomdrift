//! On-disk OSV severity cache.
//!
//! Per-advisory severity is fetched via `/v1/vulns/{id}`, which is N+1 in the
//! worst case (one HTTP roundtrip per unique advisory ID). Repeated CI runs
//! against an unchanged dependency set re-fetch the same data every time,
//! which both wastes API budget and adds tens of seconds to PR-comment
//! latency. This module memoizes severity lookups across runs.
//!
//! ## Layout
//!
//! Cache root: `<XDG_CACHE_HOME>/bomdrift/osv/` (or platform equivalent via
//! [`crate::refresh::default_cache_root`]). Each advisory is stored as
//! `<id>.json` containing:
//!
//! ```json
//! { "fetched_at": 1735689600, "severity": "HIGH" }
//! ```
//!
//! Filenames are sanitized (advisory IDs can contain `/` historically — they
//! shouldn't, but defensive). `fetched_at` is unix-seconds since epoch.
//!
//! ## TTL
//!
//! Entries older than [`CACHE_TTL_SECS`] (24h) are treated as misses on read
//! and the on-disk file is left in place — a subsequent `put` overwrites it
//! atomically. We don't sweep proactively; the cache is bounded by the
//! advisory-corpus size (~tens of MB of severity entries even at the limit
//! of OSV's database, well below typical XDG-cache budgets).
//!
//! ## Failure semantics
//!
//! Every operation is best-effort: a corrupted file, a missing cache root,
//! or a permission error returns `None` from `get` and silently drops a
//! `put`. The cache is purely an optimization; the OSV enricher's contract
//! (best-effort, surface warnings, never block rendering) is preserved.
//!
//! ## --no-osv-cache
//!
//! `bomdrift diff --no-osv-cache` skips both reads and writes. Useful for
//! reproducibility audits and for the rare case where a stale severity
//! (within the 24h TTL) is actively misleading.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::enrich::Severity;

/// 24 hours. Long enough that successive PR pushes within a typical work
/// session hit cache; short enough that severity downgrades / corrections
/// propagate within a day.
pub const CACHE_TTL_SECS: u64 = 24 * 60 * 60;

/// Resolve the effective TTL in seconds. When `override_hours` is `Some`
/// (driven by `--cache-ttl-hours` / `[diff] cache_ttl_hours`), uses that
/// uniformly across OSV / EPSS / KEV / Registry caches; otherwise falls
/// back to the [`CACHE_TTL_SECS`] default. Single source of truth so the
/// override semantics stay identical across enrichers.
pub fn effective_ttl_secs(override_hours: Option<u64>) -> u64 {
    match override_hours {
        Some(h) if h > 0 => h.saturating_mul(3600),
        _ => CACHE_TTL_SECS,
    }
}

/// Subdirectory under the cache root where per-advisory entries live.
const OSV_SUBDIR: &str = "osv";

#[derive(Debug, Serialize, Deserialize)]
struct CacheEntry {
    fetched_at: u64,
    severity: Severity,
    /// Cross-database aliases captured at fetch time. Newly added in
    /// v0.9. Old cache entries without this field deserialize with an
    /// empty vec; downstream consumers tolerate the empty case by
    /// falling back to the primary advisory ID.
    #[serde(default)]
    aliases: Vec<String>,
}

/// Filesystem-backed severity cache. Construct via [`Cache::open`] (production)
/// or [`Cache::with_root`] (tests, when an explicit root is needed).
pub struct Cache {
    root: PathBuf,
    now_secs: fn() -> u64,
    ttl_secs: u64,
}

impl Cache {
    /// Open the cache rooted at the platform's XDG cache directory. Returns
    /// `None` when the platform doesn't expose one (extremely rare; degraded
    /// to "always miss" so callers don't have to special-case).
    pub fn open() -> Option<Self> {
        Self::open_with_ttl(None)
    }

    /// Like [`Cache::open`] but lets the caller override the on-disk TTL
    /// (driven by `--cache-ttl-hours`). `None` means use the default.
    pub fn open_with_ttl(ttl_hours: Option<u64>) -> Option<Self> {
        let root = crate::refresh::default_cache_root().ok()?.join(OSV_SUBDIR);
        Some(Self {
            root,
            now_secs: default_now_secs,
            ttl_secs: effective_ttl_secs(ttl_hours),
        })
    }

    /// Test-only entry point that lets callers point the cache at an explicit
    /// directory and pin the clock for deterministic TTL assertions.
    #[cfg(test)]
    pub fn with_root(root: PathBuf, now_secs: fn() -> u64) -> Self {
        Self {
            root,
            now_secs,
            ttl_secs: CACHE_TTL_SECS,
        }
    }

    /// Look up cached severity + aliases for `advisory_id`. Returns
    /// `None` on cache miss, missing file, parse error, or expired
    /// entry — every failure mode collapses to "go fetch fresh".
    pub fn get(&self, advisory_id: &str) -> Option<Severity> {
        self.get_full(advisory_id).map(|(s, _)| s)
    }

    /// Like [`Cache::get`] but also returns the aliases stored in the
    /// cache entry. Empty when the entry was written by a pre-v0.9
    /// build.
    pub fn get_full(&self, advisory_id: &str) -> Option<(Severity, Vec<String>)> {
        let path = self.path_for(advisory_id);
        let body = std::fs::read(&path).ok()?;
        let entry: CacheEntry = serde_json::from_slice(&body).ok()?;
        let now = (self.now_secs)();
        if now.saturating_sub(entry.fetched_at) > self.ttl_secs {
            return None;
        }
        Some((entry.severity, entry.aliases))
    }

    /// Persist `severity` for `advisory_id`. Best-effort: filesystem errors
    /// are silently dropped because the caller has the live response in hand
    /// and we never want a write failure to corrupt the in-memory data path.
    pub fn put(&self, advisory_id: &str, severity: Severity) {
        self.put_full(advisory_id, severity, &[]);
    }

    /// Like [`Cache::put`] but stores aliases alongside the severity.
    pub fn put_full(&self, advisory_id: &str, severity: Severity, aliases: &[String]) {
        if std::fs::create_dir_all(&self.root).is_err() {
            return;
        }
        let entry = CacheEntry {
            fetched_at: (self.now_secs)(),
            severity,
            aliases: aliases.to_vec(),
        };
        let Ok(body) = serde_json::to_vec(&entry) else {
            return;
        };
        let target = self.path_for(advisory_id);
        let mut tmp = target.as_os_str().to_owned();
        tmp.push(".tmp");
        let tmp = PathBuf::from(tmp);
        if std::fs::write(&tmp, body).is_err() {
            return;
        }
        let _ = std::fs::rename(&tmp, &target);
    }

    fn path_for(&self, advisory_id: &str) -> PathBuf {
        self.root.join(format!("{}.json", sanitize(advisory_id)))
    }
}

fn default_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Map an advisory ID to a filesystem-safe stem. OSV-canonical IDs (`GHSA-…`,
/// `CVE-…`, `MAL-…`) are already safe; this is defensive against malformed
/// entries that contain `/`, `\`, or other path-y bytes.
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

/// Convenience that wraps `Cache::open` and applies the contract of
/// `--no-osv-cache`: when `disabled` is true, return `None` so callers
/// uniformly skip both reads and writes.
pub fn open_unless_disabled(disabled: bool) -> Option<Cache> {
    open_unless_disabled_with_ttl(disabled, None)
}

/// Like [`open_unless_disabled`] but threads the `--cache-ttl-hours`
/// override through to [`Cache::open_with_ttl`].
pub fn open_unless_disabled_with_ttl(disabled: bool, ttl_hours: Option<u64>) -> Option<Cache> {
    if disabled {
        None
    } else {
        Cache::open_with_ttl(ttl_hours)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_clock() -> u64 {
        1_700_000_000
    }
    fn one_day_later() -> u64 {
        1_700_000_000 + CACHE_TTL_SECS + 1
    }

    fn tempdir_unique(stem: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "bomdrift-cache-test-{stem}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn put_then_get_roundtrips_severity() {
        let dir = tempdir_unique("roundtrip");
        let cache = Cache::with_root(dir.clone(), fixed_clock);
        cache.put("GHSA-xxxx-yyyy-zzzz", Severity::Critical);
        let got = cache.get("GHSA-xxxx-yyyy-zzzz");
        assert_eq!(got, Some(Severity::Critical));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn put_full_roundtrips_aliases() {
        let dir = tempdir_unique("aliases");
        let cache = Cache::with_root(dir.clone(), fixed_clock);
        cache.put_full(
            "GHSA-aliases-1",
            Severity::High,
            &["CVE-2024-1".to_string(), "CVE-2024-2".to_string()],
        );
        let (sev, aliases) = cache.get_full("GHSA-aliases-1").unwrap();
        assert_eq!(sev, Severity::High);
        assert_eq!(
            aliases,
            vec!["CVE-2024-1".to_string(), "CVE-2024-2".to_string()]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn get_returns_none_for_missing_advisory() {
        let dir = tempdir_unique("miss");
        let cache = Cache::with_root(dir.clone(), fixed_clock);
        assert_eq!(cache.get("CVE-NEVER-CACHED"), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn expired_entry_returns_none() {
        let dir = tempdir_unique("expired");
        // Write at t=fixed_clock; read at t = fixed_clock + TTL + 1.
        let writer = Cache::with_root(dir.clone(), fixed_clock);
        writer.put("GHSA-aged", Severity::High);
        let reader = Cache::with_root(dir.clone(), one_day_later);
        assert_eq!(
            reader.get("GHSA-aged"),
            None,
            "entry past TTL must read as miss"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn entry_within_ttl_is_returned() {
        let dir = tempdir_unique("fresh");
        let writer = Cache::with_root(dir.clone(), fixed_clock);
        writer.put("GHSA-fresh", Severity::Medium);
        // Read 23 hours later — just inside the TTL.
        let almost_a_day = || 1_700_000_000 + (23 * 60 * 60);
        let reader = Cache::with_root(dir.clone(), almost_a_day);
        assert_eq!(reader.get("GHSA-fresh"), Some(Severity::Medium));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn corrupt_cache_file_is_treated_as_miss() {
        let dir = tempdir_unique("corrupt");
        std::fs::write(dir.join("CVE-2025-broken.json"), "<not json>").unwrap();
        let cache = Cache::with_root(dir.clone(), fixed_clock);
        assert_eq!(
            cache.get("CVE-2025-broken"),
            None,
            "unparseable entry must miss, not panic"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sanitize_replaces_path_separators_with_underscore() {
        assert_eq!(sanitize("GHSA-abc-def"), "GHSA-abc-def");
        assert_eq!(sanitize("weird/id"), "weird_id");
        assert_eq!(sanitize("../../etc/passwd"), ".._.._etc_passwd");
    }

    #[test]
    fn put_uses_temp_file_then_rename_no_torn_writes() {
        // After a put, the temp file must NOT be present on disk.
        let dir = tempdir_unique("atomic");
        let cache = Cache::with_root(dir.clone(), fixed_clock);
        cache.put("GHSA-atomic", Severity::Low);
        let entries: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
            .collect();
        assert!(
            !entries.iter().any(|n| n.ends_with(".tmp")),
            "leftover temp file in {entries:?}"
        );
        assert!(
            entries.iter().any(|n| n == "GHSA-atomic.json"),
            "expected committed file in {entries:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn open_unless_disabled_respects_flag() {
        // Sanity: the disabled path returns None unconditionally.
        assert!(open_unless_disabled(true).is_none());
        // Enabled path may or may not return Some depending on the host's
        // ProjectDirs availability; just assert the function doesn't panic.
        let _ = open_unless_disabled(false);
    }

    #[test]
    fn effective_ttl_secs_falls_back_to_default_when_none() {
        assert_eq!(effective_ttl_secs(None), CACHE_TTL_SECS);
        // 0 is a degenerate override; treat it as "use default" rather
        // than "never cache" so a misread config doesn't disable the cache.
        assert_eq!(effective_ttl_secs(Some(0)), CACHE_TTL_SECS);
    }

    #[test]
    fn effective_ttl_secs_converts_hours_to_seconds() {
        assert_eq!(effective_ttl_secs(Some(1)), 3600);
        assert_eq!(effective_ttl_secs(Some(48)), 48 * 3600);
    }

    #[test]
    fn cache_with_overridden_ttl_expires_independently_of_const() {
        // Build a Cache whose TTL is 1 hour, then read past that window.
        // Validates that the per-instance ttl_secs (not CACHE_TTL_SECS)
        // gates expiration.
        let dir = tempdir_unique("override-ttl");
        let writer = Cache::with_root(dir.clone(), fixed_clock);
        writer.put("GHSA-override", Severity::Low);
        let mut reader = Cache::with_root(dir.clone(), || 1_700_000_000 + 3600 + 1);
        reader.ttl_secs = effective_ttl_secs(Some(1));
        assert_eq!(
            reader.get("GHSA-override"),
            None,
            "1h-TTL cache must miss after 1h+1s"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
