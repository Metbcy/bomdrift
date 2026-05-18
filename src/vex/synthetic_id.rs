//! Synthetic IDs bomdrift uses for non-CVE finding kinds. The same scheme
//! is used by `--emit-vex` (Phase H) and `--vex` (this module) so users
//! can write `not_affected` statements against typosquat / version-jump /
//! maintainer-age / license-violation findings.
//!
//! Format: `bomdrift.<kind>:<purl>[:<extra>...]`.
//!
//! `<purl>` is either a full Package URL (begins `pkg:`) or, when the
//! component lacks one, the bare component name. Round-tripping via
//! [`super::parse_synthetic_id`] handles both shapes.

use crate::enrich::LicenseViolation;
use crate::enrich::maintainer::MaintainerAgeFinding;
use crate::enrich::registry::{Deprecated, MaintainerSetChanged, RecentlyPublished};
use crate::enrich::typosquat::TyposquatFinding;
use crate::enrich::version_jump::VersionJumpFinding;
use crate::model::Component;

pub fn typosquat(f: &TyposquatFinding) -> String {
    let purl = f.component.purl.as_deref().unwrap_or(&f.component.name);
    format!("bomdrift.typosquat:{purl}:{}", f.closest)
}

pub fn version_jump(f: &VersionJumpFinding) -> String {
    let purl = f.after.purl.as_deref().unwrap_or(&f.after.name);
    format!(
        "bomdrift.version-jump:{purl}:{}->{}",
        f.before_major, f.after_major
    )
}

pub fn maintainer_age(f: &MaintainerAgeFinding) -> String {
    let purl = f.component.purl.as_deref().unwrap_or(&f.component.name);
    format!("bomdrift.young-maintainer:{purl}:{}", f.top_contributor)
}

pub fn license_violation(v: &LicenseViolation) -> String {
    let purl = v.component.purl.as_deref().unwrap_or(&v.component.name);
    format!("bomdrift.license-violation:{purl}:{}", v.license)
}

/// License-change finding (same component+version, different license
/// set). Keyed only by purl — the change set is encoded in the
/// finding payload, not the synthetic id.
pub fn license_change(after: &Component) -> String {
    let purl = after.purl.as_deref().unwrap_or(&after.name);
    format!("bomdrift.license-change:{purl}")
}

pub fn recently_published(f: &RecentlyPublished) -> String {
    let purl = f.component.purl.as_deref().unwrap_or(&f.component.name);
    format!("bomdrift.recently-published:{purl}")
}

pub fn deprecated(f: &Deprecated) -> String {
    let purl = f.component.purl.as_deref().unwrap_or(&f.component.name);
    format!("bomdrift.deprecated:{purl}")
}

pub fn maintainer_set_changed(f: &MaintainerSetChanged) -> String {
    let purl = f.after.purl.as_deref().unwrap_or(&f.after.name);
    format!("bomdrift.maintainer-set-changed:{purl}")
}

/// Structured form of a parsed bomdrift synthetic finding id. See
/// [`parse_synthetic_id`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyntheticFindingKind {
    Typosquat {
        purl: String,
        closest: String,
    },
    VersionJump {
        purl: String,
        before: String,
        after: String,
    },
    MaintainerAge {
        purl: String,
        top_contributor: String,
    },
    LicenseChange {
        purl: String,
    },
    LicenseViolation {
        purl: String,
        license: String,
    },
    RecentlyPublished {
        purl: String,
    },
    Deprecated {
        purl: String,
    },
    MaintainerSetChanged {
        purl: String,
    },
}

/// Parse a bomdrift synthetic finding-id back into its structured form.
/// Round-trips against the format emitted by [`synthetic_id`].
///
/// Returns `None` for unrecognized formats — non-bomdrift advisory ids
/// (CVEs, GHSAs), malformed strings, or unknown kind tags.
///
/// The `<purl>` segment may be a full Package URL (`pkg:type/...`) or a
/// bare component name when the source SBOM lacked a purl. Both forms
/// round-trip losslessly.
pub fn parse_synthetic_id(s: &str) -> Option<SyntheticFindingKind> {
    let inner = s.strip_prefix("bomdrift.")?;
    let (kind, rest) = inner.split_once(':')?;
    let (purl, extras) = split_purl_and_extras(rest);
    match kind {
        "typosquat" => {
            if extras.is_empty() {
                return None;
            }
            Some(SyntheticFindingKind::Typosquat {
                purl,
                closest: extras.to_string(),
            })
        }
        "version-jump" => {
            let (before, after) = extras.split_once("->")?;
            if before.is_empty() || after.is_empty() {
                return None;
            }
            Some(SyntheticFindingKind::VersionJump {
                purl,
                before: before.to_string(),
                after: after.to_string(),
            })
        }
        "young-maintainer" => {
            if extras.is_empty() {
                return None;
            }
            Some(SyntheticFindingKind::MaintainerAge {
                purl,
                top_contributor: extras.to_string(),
            })
        }
        "license-violation" => {
            if extras.is_empty() {
                return None;
            }
            Some(SyntheticFindingKind::LicenseViolation {
                purl,
                license: extras.to_string(),
            })
        }
        "license-change" => {
            if !extras.is_empty() {
                return None;
            }
            Some(SyntheticFindingKind::LicenseChange { purl })
        }
        "recently-published" => {
            if !extras.is_empty() {
                return None;
            }
            Some(SyntheticFindingKind::RecentlyPublished { purl })
        }
        "deprecated" => {
            if !extras.is_empty() {
                return None;
            }
            Some(SyntheticFindingKind::Deprecated { purl })
        }
        "maintainer-set-changed" => {
            if !extras.is_empty() {
                return None;
            }
            Some(SyntheticFindingKind::MaintainerSetChanged { purl })
        }
        _ => None,
    }
}

/// Split the `<purl>[:<extra>...]` tail of a synthetic id.
///
/// A Package URL contains exactly one `:` (the `pkg:` scheme separator),
/// so when `rest` starts with `pkg:` we recombine through that first
/// colon and use the next colon as the purl/extras boundary. When the
/// component lacked a purl the emitter substitutes the bare name (no
/// `:` inside), and we split at the first colon.
fn split_purl_and_extras(rest: &str) -> (String, &str) {
    if let Some(after_pkg) = rest.strip_prefix("pkg:") {
        match after_pkg.split_once(':') {
            Some((purl_tail, extras)) => (format!("pkg:{purl_tail}"), extras),
            None => (rest.to_string(), ""),
        }
    } else {
        match rest.split_once(':') {
            Some((name, extras)) => (name.to_string(), extras),
            None => (rest.to_string(), ""),
        }
    }
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
    use crate::vex::synthetic_id;

    // ---------- v0.9.5: parse_synthetic_id ----------

    fn comp_with_purl(purl: &str) -> crate::model::Component {
        crate::model::Component {
            name: "x".into(),
            version: "1.0.0".into(),
            ecosystem: crate::model::Ecosystem::Npm,
            purl: Some(purl.into()),
            licenses: Vec::new(),
            supplier: None,
            hashes: Vec::new(),
            relationship: crate::model::Relationship::Unknown,
            source_url: None,
            bom_ref: None,
        }
    }

    #[test]
    fn parse_typosquat_round_trip() {
        let f = crate::enrich::typosquat::TyposquatFinding {
            component: comp_with_purl("pkg:npm/plain-crypto-js@4.2.1"),
            closest: "crypto-js".into(),
            score: 0.95,
        };
        let id = synthetic_id::typosquat(&f);
        assert_eq!(
            parse_synthetic_id(&id),
            Some(SyntheticFindingKind::Typosquat {
                purl: "pkg:npm/plain-crypto-js@4.2.1".into(),
                closest: "crypto-js".into(),
            })
        );
    }

    #[test]
    fn parse_version_jump_round_trip() {
        let f = crate::enrich::version_jump::VersionJumpFinding {
            before: comp_with_purl("pkg:npm/lib@1.0.0"),
            after: comp_with_purl("pkg:npm/lib@4.0.0"),
            before_major: 1,
            after_major: 4,
        };
        let id = synthetic_id::version_jump(&f);
        assert_eq!(
            parse_synthetic_id(&id),
            Some(SyntheticFindingKind::VersionJump {
                purl: "pkg:npm/lib@4.0.0".into(),
                before: "1".into(),
                after: "4".into(),
            })
        );
    }

    #[test]
    fn parse_maintainer_age_round_trip() {
        let f = crate::enrich::maintainer::MaintainerAgeFinding {
            component: comp_with_purl("pkg:npm/foo@1.0.0"),
            top_contributor: "alice".into(),
            days_old: 5,
            first_commit_at: "2026-04-26".into(),
        };
        let id = synthetic_id::maintainer_age(&f);
        assert_eq!(
            parse_synthetic_id(&id),
            Some(SyntheticFindingKind::MaintainerAge {
                purl: "pkg:npm/foo@1.0.0".into(),
                top_contributor: "alice".into(),
            })
        );
    }

    #[test]
    fn parse_license_violation_round_trip_with_spdx_with_clause() {
        let v = crate::enrich::LicenseViolation {
            component: comp_with_purl("pkg:cargo/llvm-sys@1.0.0"),
            license: "Apache-2.0 WITH LLVM-exception".into(),
            matched_rule: "deny: GPL-3.0-only".into(),
            kind: crate::enrich::LicenseViolationKind::Deny,
        };
        let id = synthetic_id::license_violation(&v);
        assert_eq!(
            parse_synthetic_id(&id),
            Some(SyntheticFindingKind::LicenseViolation {
                purl: "pkg:cargo/llvm-sys@1.0.0".into(),
                license: "Apache-2.0 WITH LLVM-exception".into(),
            })
        );
    }

    #[test]
    fn parse_license_change_round_trip() {
        let after = comp_with_purl("pkg:npm/foo@2.0.0");
        let id = synthetic_id::license_change(&after);
        assert_eq!(
            parse_synthetic_id(&id),
            Some(SyntheticFindingKind::LicenseChange {
                purl: "pkg:npm/foo@2.0.0".into(),
            })
        );
    }

    #[test]
    fn parse_recently_published_round_trip() {
        let f = crate::enrich::registry::RecentlyPublished {
            component: comp_with_purl("pkg:npm/fresh@0.1.0"),
            published_at: "2026-04-30".into(),
            days_old: 1,
        };
        let id = synthetic_id::recently_published(&f);
        assert_eq!(
            parse_synthetic_id(&id),
            Some(SyntheticFindingKind::RecentlyPublished {
                purl: "pkg:npm/fresh@0.1.0".into(),
            })
        );
    }

    #[test]
    fn parse_deprecated_round_trip() {
        let f = crate::enrich::registry::Deprecated {
            component: comp_with_purl("pkg:npm/old@1.0.0"),
            message: Some("use new-pkg".into()),
        };
        let id = synthetic_id::deprecated(&f);
        assert_eq!(
            parse_synthetic_id(&id),
            Some(SyntheticFindingKind::Deprecated {
                purl: "pkg:npm/old@1.0.0".into(),
            })
        );
    }

    #[test]
    fn parse_maintainer_set_changed_round_trip() {
        let f = crate::enrich::registry::MaintainerSetChanged {
            before: comp_with_purl("pkg:npm/foo@1.0.0"),
            after: comp_with_purl("pkg:npm/foo@2.0.0"),
            added: vec!["mallory".into()],
            removed: vec!["alice".into()],
        };
        let id = synthetic_id::maintainer_set_changed(&f);
        assert_eq!(
            parse_synthetic_id(&id),
            Some(SyntheticFindingKind::MaintainerSetChanged {
                purl: "pkg:npm/foo@2.0.0".into(),
            })
        );
    }

    #[test]
    fn parse_synthetic_id_handles_bare_name_fallback() {
        // When component lacks a purl, the emitter falls back to the
        // bare component name. Round-trip must still work.
        let mut comp = comp_with_purl("");
        comp.purl = None;
        comp.name = "anon-pkg".into();
        let f = crate::enrich::typosquat::TyposquatFinding {
            component: comp,
            closest: "real-pkg".into(),
            score: 0.9,
        };
        let id = synthetic_id::typosquat(&f);
        assert_eq!(id, "bomdrift.typosquat:anon-pkg:real-pkg");
        assert_eq!(
            parse_synthetic_id(&id),
            Some(SyntheticFindingKind::Typosquat {
                purl: "anon-pkg".into(),
                closest: "real-pkg".into(),
            })
        );
    }

    #[test]
    fn parse_synthetic_id_rejects_real_advisory_ids() {
        assert_eq!(parse_synthetic_id("CVE-2024-1234"), None);
        assert_eq!(parse_synthetic_id("GHSA-aaaa-bbbb-cccc"), None);
        assert_eq!(parse_synthetic_id("OSV-2024-9999"), None);
    }

    #[test]
    fn parse_synthetic_id_rejects_malformed_strings() {
        // Missing kind separator.
        assert_eq!(parse_synthetic_id("bomdrift."), None);
        // Unknown kind tag.
        assert_eq!(
            parse_synthetic_id("bomdrift.unknown-kind:pkg:npm/x@1.0.0"),
            None
        );
        // version-jump without `->` separator.
        assert_eq!(
            parse_synthetic_id("bomdrift.version-jump:pkg:npm/x@1.0.0:1to4"),
            None
        );
        // typosquat missing the closest segment.
        assert_eq!(
            parse_synthetic_id("bomdrift.typosquat:pkg:npm/x@1.0.0"),
            None
        );
        // license-change must NOT carry extras.
        assert_eq!(
            parse_synthetic_id("bomdrift.license-change:pkg:npm/x@1.0.0:extra"),
            None
        );
    }
}
