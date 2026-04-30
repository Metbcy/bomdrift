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
//! ## WITH-chain inheritance through compound expressions (v0.9.7+)
//!
//! Each leaf of an SPDX expression is evaluated by [`eval_leaf`] which
//! produces a [`LeafOutcome`] reflecting BOTH the base license check
//! AND the exception check. Those per-leaf outcomes are then combined
//! by the standard SPDX expression semantics:
//!
//! - **AND chain** — `X AND Y` is permitted iff X is permitted AND Y is
//!   permitted. So a denied exception on either side fails the whole
//!   conjunction. Example: `(Apache-2.0 WITH LLVM-exception) AND
//!   (BSD-3-Clause)` with `deny_exceptions=[LLVM-exception]` is denied
//!   because the LLVM leaf fails.
//! - **OR chain** — `X OR Y` is permitted iff X is permitted OR Y is
//!   permitted. A denied exception in one branch does NOT poison the
//!   OR if the sibling branch is permitted. Example: `(Apache-2.0 WITH
//!   LLVM-exception) OR (Apache-2.0 WITH Classpath-exception-2.0)` with
//!   `allow_exceptions=[LLVM-exception]` is permitted (the licensee
//!   can pick the LLVM path).
//!
//! When the combined evaluation fails, the violation's `matched_rule`
//! cites the most specific leaf-level failure (e.g.
//! `"exception:LLVM-exception denied"`) and — for compound
//! expressions — appends `" (in <raw spdx expression>)"` so reviewers
//! can locate the offending atom in the original string.
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

    // Combine per-leaf outcomes via the SPDX expression's native
    // AND/OR semantics. `Expression::evaluate` already implements
    // `AND = all true`, `OR = any true`; we feed it the boolean
    // projection of each leaf's `LeafOutcome`.
    let ok = expr.evaluate(|req| matches!(eval_leaf(req, policy), LeafOutcome::Permitted));
    if ok {
        return None;
    }

    // The expression failed. Pick the most informative leaf failure
    // for the matched_rule, preferring exception-driven causes when
    // an exception policy is active. A compound expression (more than
    // one leaf) gets `" (in <raw>)"` appended so reviewers can locate
    // the offending atom in `raw`.
    let is_compound = expr.requirements().count() > 1;
    let failure = pick_leaf_failure(expr, policy, exception_policy_active);
    let (mut matched_rule, kind) = match failure {
        Some((rule, kind)) => (rule, kind),
        None => (
            format!("not in allow list: {raw}"),
            LicenseViolationKind::NotAllowed,
        ),
    };
    if is_compound && !matched_rule.contains(" (in ") {
        matched_rule.push_str(&format!(" (in {raw})"));
    }
    Some(LicenseViolation {
        component: c.clone(),
        license: raw.to_string(),
        matched_rule,
        kind,
    })
}

/// Per-leaf evaluation outcome. Drives both the AND/OR combination
/// pass (via the boolean projection — only `Permitted` is true) and
/// the diagnostic message that cites the specific failure path.
#[derive(Debug, Clone)]
enum LeafOutcome {
    Permitted,
    /// Base license isn't on the allow list. Carries the canonical
    /// SPDX id we tried (e.g. `"GPL-3.0-only"`).
    DeniedBase(String),
    /// `WITH` exception is on the deny list.
    DeniedException(String),
    /// `allow_exceptions` is non-empty and this exception isn't on it.
    NotInAllowedException(String),
}

/// Evaluate one SPDX `LicenseReq` (a leaf of the expression tree)
/// against the policy. Both base license and `WITH` exception are
/// checked. The function does NOT consult the deny list on base
/// licenses — that's handled up-front by `evaluate_spdx` so deny
/// short-circuits the whole expression regardless of OR-branches.
fn eval_leaf(req: &spdx::LicenseReq, policy: &Policy) -> LeafOutcome {
    if !policy.allow.is_empty() {
        let names = canonical_names(&req.license);
        let base_allowed = names
            .iter()
            .any(|cand| matches_any(cand, &policy.allow).is_some());
        if !base_allowed {
            let cited = names
                .into_iter()
                .next()
                .unwrap_or_else(|| "(unknown)".to_string());
            return LeafOutcome::DeniedBase(cited);
        }
    }
    if let Some(exception) = &req.exception {
        let ex_name = exception.name;
        if policy.deny_exceptions.iter().any(|d| d == ex_name) {
            return LeafOutcome::DeniedException(ex_name.to_string());
        }
        if !policy.allow_exceptions.is_empty()
            && !policy.allow_exceptions.iter().any(|a| a == ex_name)
        {
            return LeafOutcome::NotInAllowedException(ex_name.to_string());
        }
    }
    LeafOutcome::Permitted
}

/// Walk every leaf and return the most informative failure to cite in
/// the violation's `matched_rule`. When `prefer_exception` is true and
/// any leaf has an exception-related failure, that leaf wins;
/// otherwise the first non-Permitted leaf is reported.
fn pick_leaf_failure(
    expr: &spdx::Expression,
    policy: &Policy,
    prefer_exception: bool,
) -> Option<(String, LicenseViolationKind)> {
    let outcomes: Vec<LeafOutcome> = expr
        .requirements()
        .map(|er| eval_leaf(&er.req, policy))
        .collect();
    if prefer_exception {
        for o in &outcomes {
            match o {
                LeafOutcome::DeniedException(name) => {
                    return Some((
                        format!("exception:{name} denied"),
                        LicenseViolationKind::Deny,
                    ));
                }
                LeafOutcome::NotInAllowedException(name) => {
                    return Some((
                        format!("exception:{name} not in allow list"),
                        LicenseViolationKind::NotAllowed,
                    ));
                }
                _ => {}
            }
        }
    }
    for o in &outcomes {
        match o {
            LeafOutcome::DeniedException(name) => {
                return Some((
                    format!("exception:{name} denied"),
                    LicenseViolationKind::Deny,
                ));
            }
            LeafOutcome::NotInAllowedException(name) => {
                return Some((
                    format!("exception:{name} not in allow list"),
                    LicenseViolationKind::NotAllowed,
                ));
            }
            LeafOutcome::DeniedBase(name) => {
                return Some((
                    format!("not in allow list: {name}"),
                    LicenseViolationKind::NotAllowed,
                ));
            }
            LeafOutcome::Permitted => {}
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

    // ---------- v0.9.7 WITH-chain inheritance through compound exprs ----

    #[test]
    fn spdx_and_with_allowed_exception_permits() {
        // (Apache-2.0 WITH LLVM-exception) AND (BSD-3-Clause) with
        // both bases allowed and the exception explicitly allowed
        // → permitted via AND (both leaves Permitted).
        let cs = cs_with_added(comp(
            "foo",
            vec!["(Apache-2.0 WITH LLVM-exception) AND BSD-3-Clause"],
        ));
        let policy = Policy {
            allow: vec!["Apache-2.0".into(), "BSD-3-Clause".into()],
            allow_exceptions: vec!["LLVM-exception".into()],
            ..Default::default()
        };
        assert!(enrich(&cs, &policy).is_empty());
    }

    #[test]
    fn spdx_and_with_denied_exception_violates_and_cites_in_compound() {
        // Same expression, but the exception is denied → AND fails;
        // the matched_rule cites the exception AND appends the raw
        // compound expression so reviewers can locate the leaf.
        let raw = "(Apache-2.0 WITH LLVM-exception) AND BSD-3-Clause";
        let cs = cs_with_added(comp("foo", vec![raw]));
        let policy = Policy {
            allow: vec!["Apache-2.0".into(), "BSD-3-Clause".into()],
            deny_exceptions: vec!["LLVM-exception".into()],
            ..Default::default()
        };
        let v = enrich(&cs, &policy);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].kind, LicenseViolationKind::Deny);
        assert!(
            v[0].matched_rule.contains("LLVM-exception"),
            "matched_rule must cite the offending exception: {}",
            v[0].matched_rule
        );
        assert!(
            v[0].matched_rule.contains(&format!("(in {raw})")),
            "compound matched_rule must append (in <raw>): {}",
            v[0].matched_rule
        );
    }

    #[test]
    fn spdx_or_with_one_allowed_exception_branch_permits() {
        // (Apache-2.0 WITH LLVM-exception) OR (Apache-2.0 WITH
        // Classpath-exception-2.0) with allow_exceptions=[LLVM-exception]
        // → classpath leaf fails (not in allow list), LLVM leaf
        // permits, OR resolves to true.
        let cs = cs_with_added(comp(
            "foo",
            vec!["(Apache-2.0 WITH LLVM-exception) OR (Apache-2.0 WITH Classpath-exception-2.0)"],
        ));
        let policy = Policy {
            allow: vec!["Apache-2.0".into()],
            allow_exceptions: vec!["LLVM-exception".into()],
            ..Default::default()
        };
        assert!(
            enrich(&cs, &policy).is_empty(),
            "OR sibling permits when one branch is fully allowed"
        );
    }

    #[test]
    fn spdx_or_with_both_exceptions_denied_violates() {
        // Same expression but both exceptions denied → OR fails.
        let raw = "(Apache-2.0 WITH LLVM-exception) OR (Apache-2.0 WITH Classpath-exception-2.0)";
        let cs = cs_with_added(comp("foo", vec![raw]));
        let policy = Policy {
            allow: vec!["Apache-2.0".into()],
            deny_exceptions: vec!["LLVM-exception".into(), "Classpath-exception-2.0".into()],
            ..Default::default()
        };
        let v = enrich(&cs, &policy);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].kind, LicenseViolationKind::Deny);
        // Cites at least one of the denied exceptions.
        assert!(
            v[0].matched_rule.contains("LLVM-exception")
                || v[0].matched_rule.contains("Classpath-exception-2.0"),
            "matched_rule must cite a denied exception: {}",
            v[0].matched_rule
        );
        assert!(
            v[0].matched_rule.contains("(in "),
            "compound matched_rule must append (in <raw>): {}",
            v[0].matched_rule
        );
    }

    #[test]
    fn spdx_and_inherits_exception_denial_from_either_side() {
        // (MIT) AND (Apache-2.0 WITH LLVM-exception) with the
        // exception denied → AND fails because the right leaf fails,
        // even though MIT alone is Permitted.
        let raw = "MIT AND (Apache-2.0 WITH LLVM-exception)";
        let cs = cs_with_added(comp("foo", vec![raw]));
        let policy = Policy {
            allow: vec!["MIT".into(), "Apache-2.0".into()],
            deny_exceptions: vec!["LLVM-exception".into()],
            ..Default::default()
        };
        let v = enrich(&cs, &policy);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].kind, LicenseViolationKind::Deny);
        assert!(
            v[0].matched_rule.contains("LLVM-exception"),
            "matched_rule must cite LLVM-exception: {}",
            v[0].matched_rule
        );
    }

    #[test]
    fn spdx_compound_without_exceptions_back_compat() {
        // No exceptions anywhere; the v0.9 base-license-only path
        // must still produce identical behavior. (MIT OR Apache-2.0)
        // with allow=[MIT] → permitted.
        let cs = cs_with_added(comp("foo", vec!["MIT OR Apache-2.0"]));
        let policy = Policy {
            allow: vec!["MIT".into()],
            ..Default::default()
        };
        assert!(enrich(&cs, &policy).is_empty());

        // (MIT AND BSD-3-Clause) with allow=[MIT] → BSD leaf fails,
        // AND fails. Matched rule cites the missing base license.
        let cs = cs_with_added(comp("foo", vec!["MIT AND BSD-3-Clause"]));
        let policy = Policy {
            allow: vec!["MIT".into()],
            ..Default::default()
        };
        let v = enrich(&cs, &policy);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].kind, LicenseViolationKind::NotAllowed);
        assert!(
            v[0].matched_rule.contains("BSD-3-Clause"),
            "matched_rule must cite the failing leaf: {}",
            v[0].matched_rule
        );
    }

    #[test]
    fn compound_exception_violation_fingerprint_distinct_from_base_only() {
        // SARIF/VEX roundtrip: a violation triggered by an exception
        // in a compound expression has a stable partialFingerprint
        // (synthetic id) distinct from a base-license-only violation
        // on the same component.
        let raw = "(Apache-2.0 WITH LLVM-exception) AND BSD-3-Clause";
        let v_compound = LicenseViolation {
            component: comp("foo", vec![raw]),
            license: raw.into(),
            matched_rule: format!("exception:LLVM-exception denied (in {raw})"),
            kind: LicenseViolationKind::Deny,
        };
        let v_base = LicenseViolation {
            component: comp("foo", vec!["Apache-2.0"]),
            license: "Apache-2.0".into(),
            matched_rule: "deny: Apache-2.0".into(),
            kind: LicenseViolationKind::Deny,
        };
        let id_compound = crate::vex::synthetic_id::license_violation(&v_compound);
        let id_base = crate::vex::synthetic_id::license_violation(&v_base);
        assert_ne!(
            id_compound, id_base,
            "compound exception violation must have a distinct synthetic id"
        );
        // Stability: same input produces same id.
        let id_compound_again = crate::vex::synthetic_id::license_violation(&v_compound);
        assert_eq!(id_compound, id_compound_again);
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
