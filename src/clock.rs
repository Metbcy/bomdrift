//! Single source of truth for date/time. Honors `SOURCE_DATE_EPOCH` so
//! every timestamp/date emitted by bomdrift in production paths is
//! reproducible across runs when the env var is set.
//!
//! Why one module: byte-deterministic SARIF, VEX (v0.9), baseline expiry,
//! and any audit-log-style output must agree on "now" / "today". This
//! module is the only place we read the system clock or `SOURCE_DATE_EPOCH`.

use std::env;

use anyhow::{Context, Result, anyhow};
use time::format_description::well_known::Rfc3339;
use time::macros::format_description;
use time::{Date, OffsetDateTime};

/// Returns the current time in UTC, honoring `SOURCE_DATE_EPOCH` when set.
///
/// The env is read on every call (not cached at startup) so test fixtures
/// can vary it between scenarios. If `SOURCE_DATE_EPOCH` is set but
/// malformed, we fall back to `now_utc()` rather than panic — this matches
/// the reproducible-builds spec's "best-effort" guidance.
///
/// # Example
///
/// ```
/// // SAFETY: doctest is single-threaded.
/// unsafe { std::env::set_var("SOURCE_DATE_EPOCH", "1700000000"); }
/// let t = bomdrift::clock::now();
/// assert_eq!(t.unix_timestamp(), 1700000000);
/// unsafe { std::env::remove_var("SOURCE_DATE_EPOCH"); }
/// ```
pub fn now() -> OffsetDateTime {
    if let Ok(raw) = env::var("SOURCE_DATE_EPOCH")
        && let Ok(secs) = raw.trim().parse::<i64>()
        && let Ok(t) = OffsetDateTime::from_unix_timestamp(secs)
    {
        return t;
    }
    OffsetDateTime::now_utc()
}

/// Today's date in UTC, honoring `SOURCE_DATE_EPOCH`.
pub fn today() -> Date {
    now().date()
}

/// Format an `OffsetDateTime` as RFC 3339 (e.g. `2026-04-29T12:34:56Z`).
pub fn format_rfc3339(t: OffsetDateTime) -> String {
    t.format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

/// Strict `YYYY-MM-DD` parser. Rejects non-zero-padded inputs (e.g.
/// `2026-4-29`) so baseline files don't drift between locales/tools.
pub fn parse_ymd(s: &str) -> Result<Date> {
    let fmt = format_description!("[year]-[month]-[day]");
    Date::parse(s, fmt).with_context(|| format!("invalid YYYY-MM-DD date: {s:?}"))
}

/// Format a `Date` as `YYYY-MM-DD` (zero-padded).
pub fn format_ymd(d: Date) -> String {
    let fmt = format_description!("[year]-[month]-[day]");
    d.format(fmt).unwrap_or_else(|_| "1970-01-01".to_string())
}

/// Returns true when `expires` is strictly before `today()`.
pub fn is_expired(expires: Date) -> bool {
    expires < today()
}

/// Convenience: parse a `YYYY-MM-DD` string and return whether it has
/// expired relative to `today()`. Surface parse errors to caller.
pub fn is_expired_str(s: &str) -> Result<bool> {
    parse_ymd(s).map(is_expired).map_err(|e| anyhow!("{}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Guard env mutations behind a process-wide mutex so concurrent
    /// `cargo test` threads don't trample each other.
    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        use std::sync::{Mutex, OnceLock};
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    #[test]
    fn parse_ymd_accepts_valid() {
        let d = parse_ymd("2026-04-29").unwrap();
        assert_eq!(format_ymd(d), "2026-04-29");
    }

    #[test]
    fn parse_ymd_rejects_malformed() {
        assert!(parse_ymd("2026/04/29").is_err());
        assert!(parse_ymd("not-a-date").is_err());
        assert!(parse_ymd("").is_err());
    }

    #[test]
    fn parse_ymd_rejects_non_zero_padded() {
        assert!(parse_ymd("2026-4-29").is_err());
        assert!(parse_ymd("2026-04-9").is_err());
    }

    #[test]
    fn now_honors_source_date_epoch() {
        let _g = env_lock();
        // 2026-05-01T00:00:00Z = 1777593600
        // SAFETY: env mutation guarded by process-wide mutex above.
        unsafe {
            env::set_var("SOURCE_DATE_EPOCH", "1777593600");
        }
        let t = now();
        assert_eq!(t.unix_timestamp(), 1777593600);
        assert_eq!(format_ymd(t.date()), "2026-05-01");
        unsafe {
            env::remove_var("SOURCE_DATE_EPOCH");
        }
    }

    #[test]
    fn now_is_read_per_call_not_cached() {
        let _g = env_lock();
        unsafe {
            env::set_var("SOURCE_DATE_EPOCH", "1000000000");
        }
        let a = now();
        unsafe {
            env::set_var("SOURCE_DATE_EPOCH", "2000000000");
        }
        let b = now();
        assert_ne!(a.unix_timestamp(), b.unix_timestamp());
        assert_eq!(a.unix_timestamp(), 1000000000);
        assert_eq!(b.unix_timestamp(), 2000000000);
        unsafe {
            env::remove_var("SOURCE_DATE_EPOCH");
        }
    }

    #[test]
    fn malformed_source_date_epoch_falls_back() {
        let _g = env_lock();
        unsafe {
            env::set_var("SOURCE_DATE_EPOCH", "not-a-number");
        }
        // Should not panic; returns system clock now.
        let _ = now();
        unsafe {
            env::remove_var("SOURCE_DATE_EPOCH");
        }
    }

    #[test]
    fn format_rfc3339_round_trip() {
        let t = OffsetDateTime::from_unix_timestamp(1777593600).unwrap();
        let s = format_rfc3339(t);
        assert_eq!(s, "2026-05-01T00:00:00Z");
    }

    #[test]
    fn is_expired_ordering() {
        let _g = env_lock();
        unsafe {
            env::set_var("SOURCE_DATE_EPOCH", "1777593600");
        } // 2026-05-01
        assert!(is_expired(parse_ymd("2026-04-30").unwrap()));
        assert!(!is_expired(parse_ymd("2026-05-01").unwrap()));
        assert!(!is_expired(parse_ymd("2026-05-02").unwrap()));
        unsafe {
            env::remove_var("SOURCE_DATE_EPOCH");
        }
    }
}
