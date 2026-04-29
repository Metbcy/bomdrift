//! License-policy enrichment (v0.8+).
//!
//! Distinct from [`crate::diff::ChangeSet::license_changed`] which detects
//! same-version license drift. This module evaluates each newly-added or
//! version-changed component's licenses against a configured allow / deny
//! policy and emits a [`LicenseViolation`] for every mismatch.
//!
//! ## Matching rules (v0.8 — fail-closed)
//!
//! - **Atomic** license string (no `AND`/`OR`/`WITH`/parentheses): exact
//!   compare against allow/deny. Glob: `*` suffix matches any prefix
//!   (`AGPL-*` matches `AGPL-3.0-only`, `AGPL-1.0-only`).
//! - **Compound** expression: ambiguous. With `allow_ambiguous=false`
//!   (default) AND any policy is configured (allow OR deny non-empty),
//!   emit an Ambiguous violation. With `allow_ambiguous=true`, permit.
//! - `NOASSERTION` / `OTHER` / empty: ambiguous (same fail-closed
//!   semantics).
//!
//! Deny wins when a license matches both allow and deny.
//!
//! Full SPDX expression evaluation arrives in v0.9 via the `spdx` crate.

use crate::diff::ChangeSet;
use crate::enrich::{LicenseViolation, LicenseViolationKind};
use crate::model::Component;

/// Policy configuration. Empty allow + empty deny means "no policy" — the
/// enricher returns no violations. Either or both may be set.
#[derive(Debug, Clone, Default)]
pub struct Policy {
    pub allow: Vec<String>,
    pub deny: Vec<String>,
    pub allow_ambiguous: bool,
}

impl Policy {
    pub fn is_active(&self) -> bool {
        !self.allow.is_empty() || !self.deny.is_empty()
    }
}

/// Evaluate `policy` against every Added or VersionChanged component in
/// `cs`. Returns one violation per (component, license) pair that fails.
pub fn enrich(cs: &ChangeSet, policy: &Policy) -> Vec<LicenseViolation> {
    if !policy.is_active() {
        return Vec::new();
    }
    let mut out = Vec::new();
    for c in &cs.added {
        evaluate_component(c, policy, &mut out);
    }
    for (_before, after) in &cs.version_changed {
        evaluate_component(after, policy, &mut out);
    }
    out
}

fn evaluate_component(c: &Component, policy: &Policy, out: &mut Vec<LicenseViolation>) {
    if c.licenses.is_empty() {
        // Empty license set: treat as ambiguous (we can't claim it's
        // allowed). Fail-closed when policy is active and
        // allow_ambiguous=false.
        if !policy.allow_ambiguous {
            out.push(LicenseViolation {
                component: c.clone(),
                license: "(empty)".to_string(),
                matched_rule: "ambiguous: empty license set".to_string(),
                kind: LicenseViolationKind::Ambiguous,
            });
        }
        return;
    }
    for lic in &c.licenses {
        if let Some(v) = evaluate_one(c, lic, policy) {
            out.push(v);
        }
    }
}

fn evaluate_one(c: &Component, lic: &str, policy: &Policy) -> Option<LicenseViolation> {
    let trimmed = lic.trim();
    let is_compound = is_compound_expression(trimmed);
    let is_unknown = matches!(
        trimmed.to_ascii_uppercase().as_str(),
        "" | "NOASSERTION" | "OTHER"
    );

    if is_compound || is_unknown {
        if policy.allow_ambiguous {
            return None;
        }
        return Some(LicenseViolation {
            component: c.clone(),
            license: trimmed.to_string(),
            matched_rule: format!("ambiguous: {trimmed}"),
            kind: LicenseViolationKind::Ambiguous,
        });
    }

    // Atomic. Deny wins when both match.
    if let Some(rule) = matches_any(trimmed, &policy.deny) {
        return Some(LicenseViolation {
            component: c.clone(),
            license: trimmed.to_string(),
            matched_rule: format!("deny: {rule}"),
            kind: LicenseViolationKind::Deny,
        });
    }
    if !policy.allow.is_empty() && matches_any(trimmed, &policy.allow).is_none() {
        return Some(LicenseViolation {
            component: c.clone(),
            license: trimmed.to_string(),
            matched_rule: format!("not in allow list: {trimmed}"),
            kind: LicenseViolationKind::NotAllowed,
        });
    }
    None
}

/// Return Some(rule) when `lic` matches any pattern in `patterns`. Glob
/// support is the trailing-`*` form only.
fn matches_any(lic: &str, patterns: &[String]) -> Option<String> {
    for p in patterns {
        if matches_pattern(lic, p) {
            return Some(p.clone());
        }
    }
    None
}

fn matches_pattern(lic: &str, pattern: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix('*') {
        lic.starts_with(prefix)
    } else {
        lic == pattern
    }
}

fn is_compound_expression(s: &str) -> bool {
    // Any of the SPDX operators or parens makes this a compound expression.
    if s.contains('(') || s.contains(')') {
        return true;
    }
    for token in s.split_whitespace() {
        if matches!(token, "AND" | "OR" | "WITH") {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Ecosystem, Relationship};

    fn comp(name: &str, licenses: Vec<&str>) -> Component {
        Component {
            name: name.into(),
            version: "1.0.0".into(),
            ecosystem: Ecosystem::Npm,
            purl: Some(format!("pkg:npm/{name}@1.0.0")),
            licenses: licenses.into_iter().map(String::from).collect(),
            supplier: None,
            hashes: Vec::new(),
            relationship: Relationship::Unknown,
            source_url: None,
            bom_ref: None,
        }
    }

    fn cs_with_added(c: Component) -> ChangeSet {
        ChangeSet {
            added: vec![c],
            ..Default::default()
        }
    }

    #[test]
    fn allow_pass_no_violation() {
        let cs = cs_with_added(comp("foo", vec!["MIT"]));
        let policy = Policy {
            allow: vec!["MIT".into(), "Apache-2.0".into()],
            ..Default::default()
        };
        assert!(enrich(&cs, &policy).is_empty());
    }

    #[test]
    fn deny_fail_violation() {
        let cs = cs_with_added(comp("foo", vec!["GPL-3.0-only"]));
        let policy = Policy {
            deny: vec!["GPL-3.0-only".into()],
            ..Default::default()
        };
        let v = enrich(&cs, &policy);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].kind, LicenseViolationKind::Deny);
        assert!(v[0].matched_rule.contains("GPL-3.0-only"));
    }

    #[test]
    fn glob_expansion_matches_prefix() {
        let cs = cs_with_added(comp("foo", vec!["AGPL-3.0-only"]));
        let policy = Policy {
            deny: vec!["AGPL-*".into()],
            ..Default::default()
        };
        let v = enrich(&cs, &policy);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].matched_rule, "deny: AGPL-*");
    }

    #[test]
    fn compound_ambiguous_fails_closed_by_default() {
        let cs = cs_with_added(comp("foo", vec!["(MIT OR GPL-3.0-only)"]));
        let policy = Policy {
            allow: vec!["MIT".into()],
            ..Default::default()
        };
        let v = enrich(&cs, &policy);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].kind, LicenseViolationKind::Ambiguous);
    }

    #[test]
    fn compound_ambiguous_permitted_when_flag_set() {
        let cs = cs_with_added(comp("foo", vec!["(MIT OR GPL-3.0-only)"]));
        let policy = Policy {
            allow: vec!["MIT".into()],
            allow_ambiguous: true,
            ..Default::default()
        };
        assert!(enrich(&cs, &policy).is_empty());
    }

    #[test]
    fn deny_wins_over_allow_when_both_match() {
        let cs = cs_with_added(comp("foo", vec!["GPL-3.0-only"]));
        let policy = Policy {
            allow: vec!["GPL-3.0-only".into()],
            deny: vec!["GPL-3.0-only".into()],
            ..Default::default()
        };
        let v = enrich(&cs, &policy);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].kind, LicenseViolationKind::Deny);
    }

    #[test]
    fn license_not_in_allow_list_violates() {
        let cs = cs_with_added(comp("foo", vec!["BSD-3-Clause"]));
        let policy = Policy {
            allow: vec!["MIT".into()],
            ..Default::default()
        };
        let v = enrich(&cs, &policy);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].kind, LicenseViolationKind::NotAllowed);
    }

    #[test]
    fn noassertion_treated_as_ambiguous() {
        let cs = cs_with_added(comp("foo", vec!["NOASSERTION"]));
        let policy = Policy {
            allow: vec!["MIT".into()],
            ..Default::default()
        };
        let v = enrich(&cs, &policy);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].kind, LicenseViolationKind::Ambiguous);
    }

    #[test]
    fn empty_policy_is_inactive() {
        let cs = cs_with_added(comp("foo", vec!["GPL-3.0-only"]));
        let policy = Policy::default();
        assert!(enrich(&cs, &policy).is_empty());
    }

    #[test]
    fn version_changed_components_evaluated() {
        let before = comp("foo", vec!["MIT"]);
        let mut after = comp("foo", vec!["GPL-3.0-only"]);
        after.version = "2.0.0".into();
        let cs = ChangeSet {
            version_changed: vec![(before, after)],
            ..Default::default()
        };
        let policy = Policy {
            deny: vec!["GPL-3.0-only".into()],
            ..Default::default()
        };
        let v = enrich(&cs, &policy);
        assert_eq!(v.len(), 1);
    }
}
