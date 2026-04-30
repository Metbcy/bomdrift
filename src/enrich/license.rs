//! License-policy enrichment.
//!
//! ## SPDX expression evaluation (v0.9+)
//!
//! Each license string from the SBOM is first attempted as an
//! [`spdx::Expression`]. When parsing succeeds the expression's
//! semantics drive the allow/deny decision:
//!
//! - **Deny check** — if ANY required SPDX atomic in the parsed
//!   expression matches the deny list (exact ID or `*`-suffix glob),
//!   the package is in violation. Deny is a stronger signal than
//!   allow: the resolved license could be the denied alternative, so
//!   we fail closed regardless of what the licensee picks.
//! - **Allow check** — when the allow list is non-empty, the
//!   expression must `evaluate` to true under a closure that
//!   returns true for allow-listed atomic IDs. `(MIT OR Apache-2.0)`
//!   with `allow=[MIT]` permits because the licensee can pick MIT.
//! - **`WITH` operator** — handled by `spdx`'s parser. The base
//!   license is checked against allow/deny as above. The exception
//!   identifier participates in the OR-aware `Expression::evaluate`
//!   pass via `Policy::allow_exceptions` / `Policy::deny_exceptions`
//!   (v0.9.5+): a denied exception causes that branch of an OR to
//!   fail, but a sibling branch may still permit. When both
//!   exception lists are empty, exceptions are permitted (preserves
//!   v0.9 behavior).
//!
//! When SPDX parsing FAILS (non-SPDX strings like `"Custom"`,
//! `"Proprietary"`, vendor-specific spellings) we fall back to the
//! v0.8 atomic+glob matcher so policies authored against raw strings
//! keep working.
//!
//! `NOASSERTION` / `OTHER` / empty are treated as ambiguous (same
//! fail-closed semantics as v0.8).
//!
//! ## Deprecated: `allow_ambiguous`
//!
//! In v0.8 this flag flipped fail-closed behavior on compound
//! expressions. v0.9's full SPDX evaluator handles compounds
//! correctly, so the flag is now a no-op when SPDX parsing
//! succeeds; it still works on the fallback path. A one-time
//! deprecation notice is printed to stderr when the flag is set.
//!
//! Deny wins when both allow and deny match.

use std::sync::atomic::{AtomicBool, Ordering};

use crate::diff::ChangeSet;
use crate::enrich::{LicenseViolation, LicenseViolationKind};
use crate::model::Component;

/// Policy configuration. Empty allow + empty deny means "no policy" — the
/// enricher returns no violations. Either or both may be set.
///
/// `allow_exceptions` / `deny_exceptions` (v0.9.5+) target the SPDX
/// `WITH` clause: e.g. `Apache-2.0 WITH LLVM-exception` is permitted by
/// `allow=[Apache-2.0]` but can additionally be gated by listing the
/// exception identifier (`LLVM-exception`) in `deny_exceptions`. When
/// both `allow_exceptions` and `deny_exceptions` are empty, exceptions
/// are permitted (preserves v0.9 behavior).
#[derive(Debug, Clone, Default)]
pub struct Policy {
    pub allow: Vec<String>,
    pub deny: Vec<String>,
    pub allow_ambiguous: bool,
    pub allow_exceptions: Vec<String>,
    pub deny_exceptions: Vec<String>,
}

impl Policy {
    pub fn is_active(&self) -> bool {
        !self.allow.is_empty()
            || !self.deny.is_empty()
            || !self.allow_exceptions.is_empty()
            || !self.deny_exceptions.is_empty()
    }
}

/// Evaluate `policy` against every Added or VersionChanged component in
/// `cs`. Returns one violation per (component, license) pair that fails.
pub fn enrich(cs: &ChangeSet, policy: &Policy) -> Vec<LicenseViolation> {
    if !policy.is_active() {
        return Vec::new();
    }
    if policy.allow_ambiguous {
        warn_deprecated_allow_ambiguous_once();
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
    let upper = trimmed.to_ascii_uppercase();
    let is_unknown_marker = matches!(upper.as_str(), "" | "NOASSERTION" | "OTHER");
    if is_unknown_marker {
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

    // Try SPDX parse first. Falls back to v0.8 atomic+glob matcher when
    // the string isn't a parseable SPDX expression.
    match spdx::Expression::parse(trimmed) {
        Ok(expr) => evaluate_spdx(c, trimmed, &expr, policy),
        Err(_) => evaluate_atomic_fallback(c, trimmed, policy),
    }
}

/// SPDX-evaluation path. Deny on base licenses is conservative (any
/// required atomic in deny list → violation). Allow + exception checks
/// run through `Expression::evaluate` so OR-branches resolve correctly.
fn evaluate_spdx(
    c: &Component,
    raw: &str,
    expr: &spdx::Expression,
    policy: &Policy,
) -> Option<LicenseViolation> {
    if !policy.deny.is_empty() {
        for req in expr.requirements() {
            for cand in canonical_names(&req.req.license) {
                if let Some(rule) = matches_any(&cand, &policy.deny) {
                    return Some(LicenseViolation {
                        component: c.clone(),
                        license: raw.to_string(),
                        matched_rule: format!("deny: {rule}"),
                        kind: LicenseViolationKind::Deny,
                    });
                }
            }
        }
    }

    let exception_policy_active =
        !policy.allow_exceptions.is_empty() || !policy.deny_exceptions.is_empty();
    let needs_eval = !policy.allow.is_empty() || exception_policy_active;
    if !needs_eval {
        return None;
    }

    let ok = expr.evaluate(|req| {
        if !policy.allow.is_empty() {
            let base_allowed = canonical_names(&req.license)
                .iter()
                .any(|cand| matches_any(cand, &policy.allow).is_some());
            if !base_allowed {
                return false;
            }
        }
        if let Some(exception) = &req.exception {
            let ex_name = exception.name;
            if policy.deny_exceptions.iter().any(|d| d == ex_name) {
                return false;
            }
            if !policy.allow_exceptions.is_empty()
                && !policy.allow_exceptions.iter().any(|a| a == ex_name)
            {
                return false;
            }
        }
        true
    });
    if ok {
        return None;
    }

    // Compose a useful matched_rule. Prefer exception-driven explanations
    // when an exception policy is configured AND the only failures we
    // can find are on exception clauses; fall back to base-license
    // "not in allow list" otherwise. Walks `expr.requirements()` (every
    // referenced atomic) and returns the most-specific reason.
    if exception_policy_active && let Some(reason) = first_exception_failure(expr, policy) {
        return Some(LicenseViolation {
            component: c.clone(),
            license: raw.to_string(),
            matched_rule: reason.matched_rule,
            kind: reason.kind,
        });
    }
    Some(LicenseViolation {
        component: c.clone(),
        license: raw.to_string(),
        matched_rule: format!("not in allow list: {raw}"),
        kind: LicenseViolationKind::NotAllowed,
    })
}

/// Per-requirement reason emitted when an exception policy fails. Used
/// to populate `LicenseViolation::matched_rule` so renderers can cite
/// the precise exception identifier.
struct ExceptionFailure {
    matched_rule: String,
    kind: LicenseViolationKind,
}

/// Walk `expr.requirements()` (every atomic LicenseReq referenced in
/// the expression — both AND/OR branches) and return the first
/// requirement whose `WITH` exception fails the configured exception
/// policy. The base-license allow check is intentionally NOT
/// considered here — that's reported via the generic "not in allow
/// list" path so the existing v0.9 matched_rule wording is preserved
/// for non-exception cases.
fn first_exception_failure(expr: &spdx::Expression, policy: &Policy) -> Option<ExceptionFailure> {
    for req in expr.requirements() {
        let Some(exception) = &req.req.exception else {
            continue;
        };
        let ex_name = exception.name;
        if policy.deny_exceptions.iter().any(|d| d == ex_name) {
            return Some(ExceptionFailure {
                matched_rule: format!("exception:{ex_name} denied"),
                kind: LicenseViolationKind::Deny,
            });
        }
        if !policy.allow_exceptions.is_empty()
            && !policy.allow_exceptions.iter().any(|a| a == ex_name)
        {
            return Some(ExceptionFailure {
                matched_rule: format!("exception:{ex_name} not in allow list"),
                kind: LicenseViolationKind::NotAllowed,
            });
        }
    }
    None
}

/// SPDX normalizes GNU licenses by stripping the `-only` / `-or-later`
/// suffix into a flag on the `LicenseItem`. User-authored allow/deny
/// lists usually contain the original spelling (`GPL-3.0-only`,
/// `AGPL-3.0-or-later`), so we generate every candidate name an SPDX
/// `LicenseItem` could match.
fn canonical_names(item: &spdx::LicenseItem) -> Vec<String> {
    match item {
        spdx::LicenseItem::Spdx { id, or_later } => {
            let mut names = vec![id.name.to_string()];
            if id.is_gnu() {
                if *or_later {
                    names.push(format!("{}-or-later", id.name));
                } else {
                    names.push(format!("{}-only", id.name));
                }
            } else if *or_later {
                names.push(format!("{}+", id.name));
            }
            names
        }
        spdx::LicenseItem::Other { lic_ref, .. } => vec![lic_ref.clone()],
    }
}

/// v0.8 atomic+glob fallback for non-SPDX strings.
fn evaluate_atomic_fallback(
    c: &Component,
    trimmed: &str,
    policy: &Policy,
) -> Option<LicenseViolation> {
    let is_compound = is_compound_expression(trimmed);
    if is_compound {
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

/// Return Some(rule) when `lic` matches any pattern in `patterns`.
/// Precedence: SPDX exact match > glob > raw string. Globs are
/// `*`-suffix.
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

static ALLOW_AMBIGUOUS_WARNED: AtomicBool = AtomicBool::new(false);

fn warn_deprecated_allow_ambiguous_once() {
    if ALLOW_AMBIGUOUS_WARNED.swap(true, Ordering::Relaxed) {
        return;
    }
    eprintln!(
        "warning: [license] allow_ambiguous is deprecated since v0.9; \
         SPDX expressions are now evaluated properly."
    );
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

    // ---------- v0.9 SPDX expression eval tests ----------

    #[test]
    fn spdx_or_with_one_allowed_branch_permits() {
        let cs = cs_with_added(comp("foo", vec!["(MIT OR Apache-2.0)"]));
        let policy = Policy {
            allow: vec!["MIT".into()],
            ..Default::default()
        };
        assert!(enrich(&cs, &policy).is_empty());
    }

    #[test]
    fn spdx_and_with_one_denied_branch_violates() {
        let cs = cs_with_added(comp("foo", vec!["(MIT AND GPL-3.0-only)"]));
        let policy = Policy {
            deny: vec!["GPL-3.0-only".into()],
            ..Default::default()
        };
        let v = enrich(&cs, &policy);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].kind, LicenseViolationKind::Deny);
    }

    #[test]
    fn spdx_with_exception_resolves_base_license() {
        let cs = cs_with_added(comp("foo", vec!["Apache-2.0 WITH LLVM-exception"]));
        let policy = Policy {
            allow: vec!["Apache-2.0".into()],
            ..Default::default()
        };
        assert!(enrich(&cs, &policy).is_empty());
    }

    #[test]
    fn spdx_compound_denial_wins_over_or_branches() {
        // (GPL-3.0-only OR MIT) AND BSD-3-Clause with allow=[MIT,
        // BSD-3-Clause] AND deny=[GPL-3.0-only] → violation: the
        // resolution path could pick GPL.
        let cs = cs_with_added(comp("foo", vec!["(GPL-3.0-only OR MIT) AND BSD-3-Clause"]));
        let policy = Policy {
            allow: vec!["MIT".into(), "BSD-3-Clause".into()],
            deny: vec!["GPL-3.0-only".into()],
            ..Default::default()
        };
        let v = enrich(&cs, &policy);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].kind, LicenseViolationKind::Deny);
    }

    #[test]
    fn unknown_spdx_id_falls_back_to_atomic_path() {
        // "Custom" isn't a valid SPDX ID; the atomic fallback rejects it
        // when allow is set and "Custom" isn't on the list.
        let cs = cs_with_added(comp("foo", vec!["Custom"]));
        let policy = Policy {
            allow: vec!["MIT".into()],
            ..Default::default()
        };
        let v = enrich(&cs, &policy);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].kind, LicenseViolationKind::NotAllowed);
    }

    // ---------- v0.9.5 SPDX exception allow/deny ----------

    #[test]
    fn spdx_with_exception_back_compat_when_no_exception_policy() {
        // v0.9 behavior: empty exception lists → exception is permitted.
        let cs = cs_with_added(comp("foo", vec!["Apache-2.0 WITH LLVM-exception"]));
        let policy = Policy {
            allow: vec!["Apache-2.0".into()],
            ..Default::default()
        };
        assert!(enrich(&cs, &policy).is_empty());
    }

    #[test]
    fn spdx_exception_in_deny_list_violates_and_cites_exception() {
        let cs = cs_with_added(comp("foo", vec!["Apache-2.0 WITH LLVM-exception"]));
        let policy = Policy {
            allow: vec!["Apache-2.0".into()],
            deny_exceptions: vec!["LLVM-exception".into()],
            ..Default::default()
        };
        let v = enrich(&cs, &policy);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].kind, LicenseViolationKind::Deny);
        assert_eq!(v[0].matched_rule, "exception:LLVM-exception denied");
    }

    #[test]
    fn spdx_exception_not_in_allow_list_fails_closed() {
        // allow_exceptions is non-empty but doesn't list LLVM-exception.
        let cs = cs_with_added(comp("foo", vec!["Apache-2.0 WITH LLVM-exception"]));
        let policy = Policy {
            allow: vec!["Apache-2.0".into()],
            allow_exceptions: vec!["Classpath-exception-2.0".into()],
            ..Default::default()
        };
        let v = enrich(&cs, &policy);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].kind, LicenseViolationKind::NotAllowed);
        assert_eq!(
            v[0].matched_rule,
            "exception:LLVM-exception not in allow list"
        );
    }

    #[test]
    fn spdx_exception_or_branch_permits_when_sibling_path_passes() {
        // (Apache-2.0 WITH LLVM-exception) OR (BSD-3-Clause) with
        // deny_exceptions=[LLVM-exception], allow=[Apache-2.0,
        // BSD-3-Clause] → BSD-3-Clause path passes; exception denial
        // only fails its own branch under OR semantics.
        let cs = cs_with_added(comp(
            "foo",
            vec!["(Apache-2.0 WITH LLVM-exception) OR BSD-3-Clause"],
        ));
        let policy = Policy {
            allow: vec!["Apache-2.0".into(), "BSD-3-Clause".into()],
            deny_exceptions: vec!["LLVM-exception".into()],
            ..Default::default()
        };
        assert!(
            enrich(&cs, &policy).is_empty(),
            "OR sibling without exception must permit"
        );
    }

    #[test]
    fn spdx_exception_in_allow_list_permits() {
        let cs = cs_with_added(comp("foo", vec!["Apache-2.0 WITH LLVM-exception"]));
        let policy = Policy {
            allow: vec!["Apache-2.0".into()],
            allow_exceptions: vec!["LLVM-exception".into()],
            ..Default::default()
        };
        assert!(enrich(&cs, &policy).is_empty());
    }

    #[test]
    fn exception_violation_synthetic_id_round_trips_distinctly() {
        // The synthetic id encodes the full license string (including
        // the "WITH <exception>" suffix), so an exception-driven
        // violation produces a different VEX/SARIF identity than a
        // base-license violation on the same component.
        let v_exception = LicenseViolation {
            component: comp("foo", vec!["Apache-2.0 WITH LLVM-exception"]),
            license: "Apache-2.0 WITH LLVM-exception".into(),
            matched_rule: "exception:LLVM-exception denied".into(),
            kind: LicenseViolationKind::Deny,
        };
        let v_base = LicenseViolation {
            component: comp("foo", vec!["Apache-2.0"]),
            license: "Apache-2.0".into(),
            matched_rule: "deny: Apache-2.0".into(),
            kind: LicenseViolationKind::Deny,
        };
        let id_exception = crate::vex::synthetic_id::license_violation(&v_exception);
        let id_base = crate::vex::synthetic_id::license_violation(&v_base);
        assert_ne!(
            id_exception, id_base,
            "exception-driven violation must have a distinct synthetic id"
        );
        // Round-trip the synthetic id back to the structured form.
        let parsed = crate::vex::parse_synthetic_id(&id_exception).expect("round-trips");
        match parsed {
            crate::vex::SyntheticFindingKind::LicenseViolation { license, .. } => {
                assert_eq!(license, "Apache-2.0 WITH LLVM-exception");
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }
}
