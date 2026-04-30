//! Version-jump heuristic: flag dependency upgrades that cross two or more
//! major versions in a single diff (e.g. `1.x → 4.x`).
//!
//! ## Why this matters
//!
//! Multi-major bumps in a single review are correlated with risky changes that
//! deserve extra scrutiny:
//!
//! - **Takeover swaps**: a maintainer transition followed by a major-version
//!   rename to "reset" the package identity (the xz pattern, scaled down).
//! - **Namespace reuse**: an unrelated package republished at a higher major
//!   under the same name, intentionally or after an account compromise.
//! - **"Cleaned up the dep tree" PRs**: legitimate but high-risk refactors that
//!   silently jump several majors at once and bypass the usual SemVer
//!   guard-rails reviewers rely on.
//!
//! The heuristic is intentionally cheap (no I/O, no new dependencies) and
//! always informational — it never trips fail-on. The threshold is a delta of
//! `>= 2`: a single major bump (1 → 2) is the normal SemVer signal that
//! humans already understand, while two or more is the unusual case worth
//! surfacing.
//!
//! ## Major-version extraction
//!
//! Hand-rolled, ~5 lines. We deliberately avoid the `semver` crate: full
//! SemVer parsing is unnecessary when only the major number is consulted, and
//! pulling the dep would add transitive weight for no functional gain.
//!
//! Accepted forms (each yields a `Some(major)`):
//!
//! - `1.2.3`            → 1
//! - `v1.0.0`           → 1 (leading `v` tolerated)
//! - `2.5.3-beta.1`     → 2 (pre-release suffix ignored)
//! - `3.0.0+build.123`  → 3 (build metadata ignored)
//! - `4` / `4-rc.1`     → 4 (no minor required)
//!
//! Rejected forms (yield `None`, the pair is skipped — never flagged):
//!
//! - empty string
//! - non-numeric (`latest`, `nightly`, `main`)
//! - leading-zero numbers (`01.2.3`) — ambiguous and almost always a sign of
//!   a non-SemVer scheme; safer to skip than misinterpret.

use serde::Serialize;

use crate::diff::ChangeSet;
use crate::model::Component;

/// Minimum delta in the major version for a pair to be flagged. A single major
/// bump (`1 → 2`) is the standard SemVer signal and isn't surfaced — only
/// delta `>= 2` is unusual enough to warrant explicit review.
pub const MIN_MAJOR_DELTA: u32 = 2;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct VersionJumpFinding {
    pub before: Component,
    pub after: Component,
    pub before_major: u32,
    pub after_major: u32,
}

pub fn enrich(cs: &ChangeSet) -> Vec<VersionJumpFinding> {
    enrich_with(cs, None)
}

/// Same as [`enrich`] but accepts an override for the minimum major-version
/// delta. `None` falls back to [`MIN_MAJOR_DELTA`]. Used by the
/// `--multi-major-delta` CLI flag (v0.9.7+).
pub fn enrich_with(cs: &ChangeSet, min_major_delta: Option<u32>) -> Vec<VersionJumpFinding> {
    let threshold = min_major_delta.unwrap_or(MIN_MAJOR_DELTA);
    let mut out = Vec::new();
    for (before, after) in &cs.version_changed {
        let Some(before_major) = extract_major(&before.version) else {
            continue;
        };
        let Some(after_major) = extract_major(&after.version) else {
            continue;
        };
        if after_major.saturating_sub(before_major) >= threshold {
            out.push(VersionJumpFinding {
                before: before.clone(),
                after: after.clone(),
                before_major,
                after_major,
            });
        }
    }
    out
}

/// Extract the major-version integer from a version string, tolerating a
/// leading `v`, pre-release suffix (`-...`), and build metadata (`+...`).
/// Returns `None` for empty input, non-numeric majors, or leading-zero majors
/// (see module docs for rationale).
fn extract_major(version: &str) -> Option<u32> {
    let s = version.strip_prefix('v').unwrap_or(version);
    let head = s.split(['.', '-', '+']).next()?;
    if head.is_empty() {
        return None;
    }
    if head.len() > 1 && head.starts_with('0') {
        return None;
    }
    head.parse::<u32>().ok()
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
    use crate::model::{Component, Ecosystem, Relationship};

    fn comp(name: &str, version: &str) -> Component {
        Component {
            name: name.to_string(),
            version: version.to_string(),
            ecosystem: Ecosystem::Npm,
            purl: Some(format!("pkg:npm/{name}@{version}")),
            licenses: Vec::new(),
            supplier: None,
            hashes: Vec::new(),
            relationship: Relationship::Unknown,
            source_url: None,
            bom_ref: None,
        }
    }

    #[test]
    fn extract_major_plain() {
        assert_eq!(extract_major("1.2.3"), Some(1));
        assert_eq!(extract_major("0.1.0"), Some(0));
        assert_eq!(extract_major("42.0.0"), Some(42));
    }

    #[test]
    fn extract_major_v_prefix() {
        assert_eq!(extract_major("v2.0.0"), Some(2));
        assert_eq!(extract_major("v10.5.1"), Some(10));
    }

    #[test]
    fn extract_major_pre_release_suffix() {
        assert_eq!(extract_major("2.5.3-beta.1"), Some(2));
        assert_eq!(extract_major("4-rc.1"), Some(4));
    }

    #[test]
    fn extract_major_build_metadata() {
        assert_eq!(extract_major("3.0.0+build.7"), Some(3));
        assert_eq!(extract_major("3+build.123"), Some(3));
    }

    #[test]
    fn extract_major_returns_none_on_empty() {
        assert_eq!(extract_major(""), None);
        assert_eq!(extract_major("v"), None);
    }

    #[test]
    fn extract_major_returns_none_on_non_numeric() {
        assert_eq!(extract_major("latest"), None);
        assert_eq!(extract_major("nightly"), None);
        assert_eq!(extract_major("main"), None);
    }

    #[test]
    fn extract_major_rejects_leading_zero() {
        assert_eq!(extract_major("01.2.3"), None);
        assert_eq!(extract_major("007"), None);
    }

    #[test]
    fn enrich_flags_delta_of_three() {
        let cs = ChangeSet {
            version_changed: vec![(comp("a", "1.2.3"), comp("a", "4.0.0"))],
            ..Default::default()
        };
        let findings = enrich(&cs);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].before_major, 1);
        assert_eq!(findings[0].after_major, 4);
    }

    #[test]
    fn enrich_flags_delta_of_two() {
        let cs = ChangeSet {
            version_changed: vec![(comp("a", "1.0.0"), comp("a", "3.0.0"))],
            ..Default::default()
        };
        let findings = enrich(&cs);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn enrich_does_not_flag_single_major_bump() {
        let cs = ChangeSet {
            version_changed: vec![(comp("a", "1.0.0"), comp("a", "2.0.0"))],
            ..Default::default()
        };
        assert!(enrich(&cs).is_empty());
    }

    #[test]
    fn enrich_does_not_flag_minor_or_patch_bump() {
        let cs = ChangeSet {
            version_changed: vec![
                (comp("a", "1.0.0"), comp("a", "1.5.0")),
                (comp("b", "2.3.4"), comp("b", "2.3.5")),
            ],
            ..Default::default()
        };
        assert!(enrich(&cs).is_empty());
    }

    #[test]
    fn enrich_skips_pairs_with_unparseable_versions() {
        let cs = ChangeSet {
            version_changed: vec![
                (comp("a", "latest"), comp("a", "4.0.0")),
                (comp("b", "1.0.0"), comp("b", "nightly")),
                (comp("c", "1.0.0"), comp("c", "4.0.0")),
            ],
            ..Default::default()
        };
        let findings = enrich(&cs);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].after.name, "c");
    }

    #[test]
    fn enrich_returns_empty_for_empty_changeset() {
        let findings = enrich(&ChangeSet::default());
        assert!(findings.is_empty());
    }

    #[test]
    fn enrich_returns_empty_for_added_only_changeset() {
        let cs = ChangeSet {
            added: vec![comp("a", "1.0.0"), comp("b", "9.9.9")],
            removed: vec![comp("c", "1.0.0")],
            ..Default::default()
        };
        assert!(enrich(&cs).is_empty());
    }

    // ---- v0.9.7 multi-major-delta knob -----------------------------------

    #[test]
    fn enrich_with_default_threshold_matches_enrich() {
        let cs = ChangeSet {
            version_changed: vec![(comp("a", "1.0.0"), comp("a", "4.0.0"))],
            ..Default::default()
        };
        // Default threshold (None) = 2; trips on 1.x → 4.x.
        let findings = enrich_with(&cs, None);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn enrich_with_threshold_one_trips_on_single_major_bump() {
        // delta=1 makes a single major bump (1.x → 2.x) trip — useful
        // for adopters who want every cross-major upgrade flagged.
        let cs = ChangeSet {
            version_changed: vec![(comp("a", "1.0.0"), comp("a", "2.0.0"))],
            ..Default::default()
        };
        // Default would NOT trip:
        assert!(enrich(&cs).is_empty());
        // Override does trip:
        let findings = enrich_with(&cs, Some(1));
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn enrich_with_high_threshold_suppresses_smaller_jumps() {
        // delta=5 means even 1.x → 4.x doesn't trip.
        let cs = ChangeSet {
            version_changed: vec![(comp("a", "1.0.0"), comp("a", "4.0.0"))],
            ..Default::default()
        };
        // Default trips:
        assert_eq!(enrich(&cs).len(), 1);
        // High threshold suppresses:
        assert!(enrich_with(&cs, Some(5)).is_empty());
    }

    #[test]
    fn enrich_preserves_input_order() {
        let cs = ChangeSet {
            version_changed: vec![
                (comp("alpha", "1.0.0"), comp("alpha", "5.0.0")),
                (comp("beta", "2.0.0"), comp("beta", "4.0.0")),
                (comp("gamma", "3.0.0"), comp("gamma", "9.0.0")),
            ],
            ..Default::default()
        };
        let findings = enrich(&cs);
        assert_eq!(findings.len(), 3);
        assert_eq!(findings[0].after.name, "alpha");
        assert_eq!(findings[1].after.name, "beta");
        assert_eq!(findings[2].after.name, "gamma");
    }

    // ---- Property-based tests --------------------------------------------

    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(2048))]

        /// `extract_major` must never panic on arbitrary input. The
        /// function is called on every version string in a ChangeSet's
        /// version_changed pairs; a panic here would crash the diff
        /// pipeline mid-render.
        #[test]
        fn extract_major_does_not_panic(s in ".*") {
            let _ = extract_major(&s);
        }

        /// Numeric majors (with no prefix or pre-release / build metadata)
        /// must round-trip correctly. The `prop_filter` excludes the
        /// leading-zero case (which the function deliberately rejects)
        /// and over-large values that don't fit in u32.
        #[test]
        fn extract_major_round_trips_well_formed_numerics(major in 1u32..=10_000) {
            let v = format!("{major}.0.0");
            prop_assert_eq!(extract_major(&v), Some(major));
            let with_v = format!("v{major}.0.0");
            prop_assert_eq!(extract_major(&with_v), Some(major));
            let with_pre = format!("{major}.0.0-rc.1");
            prop_assert_eq!(extract_major(&with_pre), Some(major));
        }

        /// Strings containing non-ASCII unicode or control characters
        /// must not panic. The regex-free implementation walks bytes;
        /// this exercises the byte-level paths.
        #[test]
        fn extract_major_handles_unicode_without_panic(prefix in "\\PC*", major in 1u32..1000) {
            // Mix arbitrary unicode prefix with a well-formed version.
            // The function should treat the prefix as garbage (likely
            // returning None) but never panic.
            let s = format!("{prefix}{major}.0.0");
            let _ = extract_major(&s);
        }
    }
}
