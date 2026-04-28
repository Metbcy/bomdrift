//! Typosquat enrichment: flag added components whose name is suspiciously
//! similar to a popular package in the same ecosystem.
//!
//! v0 ships an embedded snapshot of the top-1000 npm packages by depended-upon
//! count (see `data/npm-top1k.txt`). Each newly added `Ecosystem::Npm` component
//! is scored against the list with two complementary rules.
//!
//! ## Filtering & scoring rules
//!
//! 1. **Exact match (case-insensitive) → skip**. The candidate IS a popular
//!    package, not a squat of one.
//! 2. **Likely-legit ecosystem extension → skip per-comparison**. When the
//!    candidate starts with a legit name followed by a separator
//!    (`-`, `_`, `.`, `/`), this matches the well-established convention for
//!    extension packages (`react-router`, `axios-retry`, `lodash-es`,
//!    `eslint-plugin-react`). Treating these as squats would produce constant
//!    false positives on legitimate packages.
//! 3. **Suffix containment with a substantial added prefix → boost**. When the
//!    candidate ends with a legit name (≥ 5 chars) AND the added prefix is
//!    longer than 3 characters, the score is boosted to at least
//!    [`SUFFIX_BOOST_SCORE`]. This is the textbook typosquat pattern:
//!    `plain-crypto-js`, `safe-axios`, `secure-lodash`. The base
//!    Jaro-Winkler similarity for these is low (the prefix kills it) but the
//!    deceptive intent is unmistakable.
//! 4. Otherwise: plain Jaro-Winkler. Threshold [`SIMILARITY_THRESHOLD`] (0.92)
//!    catches single-character typos like `cross-env` → `crossenv` (~0.98)
//!    and `express` → `expresss` (~0.97), while leaving longer divergences
//!    like `react` → `react-router` (~0.88) below the threshold.
//!
//! ## Reputational care
//!
//! The renderer wording is "is similar to {legit}", never "is a typosquat".
//! Flagging a legitimate package as a malicious squat in a public PR comment
//! is a real reputational harm to the package author; the human reviewing the
//! PR is the analyst making the determination.

use std::collections::HashSet;
use std::sync::OnceLock;

use strsim::jaro_winkler;

use crate::diff::ChangeSet;
use crate::model::{Component, Ecosystem};

const NPM_TOP_LIST: &str = include_str!("../../data/npm-top1k.txt");

/// Minimum Jaro-Winkler score (or boosted score) for a pairing to be reported.
pub const SIMILARITY_THRESHOLD: f64 = 0.92;

/// Score assigned when suffix-containment boost fires. Above the threshold so
/// the finding always surfaces, but expressed as a score (not a hard 1.0) so
/// the user can read intensity off the rendered table without misreading
/// boosted hits as "perfect" matches.
const SUFFIX_BOOST_SCORE: f64 = 0.95;

/// Minimum length of a legit name for the prefix-extension and suffix-boost
/// rules to apply. Short names (`fs`, `is`, `q`) are too generic — applying
/// the structural rules to them produces noise without signal.
const MIN_LEGIT_LEN_FOR_STRUCTURAL_RULES: usize = 5;

/// A candidate must add more than this many characters of prefix on top of
/// a contained legit name for the suffix boost to apply. Smaller deltas are
/// usually trivial typos (`expresss` vs `express`) which Jaro-Winkler already
/// handles, or intentional pluralizations (`react` vs `reacts`).
const SUFFIX_BOOST_MIN_DELTA: usize = 3;

#[derive(Debug, Clone, PartialEq)]
pub struct TyposquatFinding {
    pub component: Component,
    pub closest: String,
    pub score: f64,
}

pub fn enrich(cs: &ChangeSet) -> Vec<TyposquatFinding> {
    let legit_set = npm_legit_set();
    let legit_list = npm_legit_list();
    let mut out = Vec::new();
    for comp in &cs.added {
        if comp.ecosystem != Ecosystem::Npm {
            continue;
        }
        let candidate = comp.name.to_lowercase();
        if legit_set.contains(candidate.as_str()) {
            continue;
        }
        if let Some((closest, score)) = best_match(&candidate, legit_list) {
            if score >= SIMILARITY_THRESHOLD {
                out.push(TyposquatFinding {
                    component: comp.clone(),
                    closest: closest.to_string(),
                    score,
                });
            }
        }
    }
    out
}

fn best_match<'a>(candidate: &str, legit: &'a [&'a str]) -> Option<(&'a str, f64)> {
    let mut best: Option<(&'a str, f64)> = None;
    for &name in legit {
        if name == candidate {
            continue;
        }
        if is_likely_legit_extension(candidate, name) {
            continue;
        }
        let mut score = jaro_winkler(candidate, name);
        if has_suspicious_suffix_containment(candidate, name) {
            score = score.max(SUFFIX_BOOST_SCORE);
        }
        match best {
            Some((_, b)) if score <= b => {}
            _ => best = Some((name, score)),
        }
    }
    best
}

/// True when `candidate` looks like a legitimate extension package built on top
/// of `legit` (e.g. `axios-retry` extending `axios`). The convention across the
/// npm ecosystem is `<popular-name><separator><suffix>`, so we only honor the
/// pattern when the leading separator is one of `-`, `_`, `.`, `/`.
fn is_likely_legit_extension(candidate: &str, legit: &str) -> bool {
    if legit.len() < MIN_LEGIT_LEN_FOR_STRUCTURAL_RULES {
        return false;
    }
    if !candidate.starts_with(legit) {
        return false;
    }
    is_separator_byte(candidate.as_bytes().get(legit.len()).copied())
}

/// True when `candidate` ends with `legit` AND has a substantial added prefix.
/// This is the malicious-prefix typosquat pattern (`plain-crypto-js` →
/// `crypto-js`); Jaro-Winkler scores it low because of all the prepended
/// characters, but the suffix relationship is itself the signal.
fn has_suspicious_suffix_containment(candidate: &str, legit: &str) -> bool {
    if legit.len() < MIN_LEGIT_LEN_FOR_STRUCTURAL_RULES {
        return false;
    }
    if candidate.len() <= legit.len() + SUFFIX_BOOST_MIN_DELTA {
        return false;
    }
    candidate.ends_with(legit)
}

fn is_separator_byte(b: Option<u8>) -> bool {
    matches!(b, Some(b'-' | b'_' | b'.' | b'/'))
}

fn npm_legit_list() -> &'static [&'static str] {
    static LIST: OnceLock<Vec<&'static str>> = OnceLock::new();
    LIST.get_or_init(|| {
        NPM_TOP_LIST
            .lines()
            .map(str::trim)
            .filter(|s| !s.is_empty() && !s.starts_with('#'))
            .collect()
    })
}

fn npm_legit_set() -> &'static HashSet<&'static str> {
    static SET: OnceLock<HashSet<&'static str>> = OnceLock::new();
    SET.get_or_init(|| npm_legit_list().iter().copied().collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Relationship;

    fn comp(name: &str) -> Component {
        Component {
            name: name.to_string(),
            version: "1.0.0".to_string(),
            ecosystem: Ecosystem::Npm,
            purl: Some(format!("pkg:npm/{name}@1.0.0")),
            licenses: Vec::new(),
            supplier: None,
            hashes: Vec::new(),
            relationship: Relationship::Unknown,
            source_url: None,
            bom_ref: None,
        }
    }

    fn cs_added(components: Vec<Component>) -> ChangeSet {
        ChangeSet {
            added: components,
            ..Default::default()
        }
    }

    #[test]
    fn embedded_list_loads_thousand_names() {
        let list = npm_legit_list();
        assert!(
            list.len() >= 900,
            "expected ~1000 npm names, got {}",
            list.len()
        );
        assert!(list.contains(&"crypto-js"), "crypto-js must be in list");
        assert!(list.contains(&"cross-env"), "cross-env must be in list");
        assert!(list.contains(&"axios"), "axios must be in list");
        assert!(list.contains(&"react"), "react must be in list");
        assert!(
            list.contains(&"react-router"),
            "react-router must be in list (covers the no-flag test)"
        );
    }

    #[test]
    fn crossenv_flags_against_cross_env_via_jaro_winkler() {
        let findings = enrich(&cs_added(vec![comp("crossenv")]));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].closest, "cross-env");
        assert!(
            findings[0].score >= SIMILARITY_THRESHOLD,
            "score {} below threshold",
            findings[0].score
        );
    }

    #[test]
    fn plain_crypto_js_flags_against_crypto_js_via_suffix_boost() {
        // The axios-incident demo: malicious package name prepends "plain-" to
        // a real popular package. Jaro-Winkler alone scores this at ~0.76 (the
        // prepended chars hurt) but the suffix-containment rule catches it.
        let findings = enrich(&cs_added(vec![comp("plain-crypto-js")]));
        assert_eq!(findings.len(), 1, "plain-crypto-js should fire");
        assert_eq!(findings[0].closest, "crypto-js");
        assert!(findings[0].score >= SIMILARITY_THRESHOLD);
    }

    #[test]
    fn safe_axios_flags_against_axios_via_suffix_boost() {
        let findings = enrich(&cs_added(vec![comp("safe-axios")]));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].closest, "axios");
    }

    #[test]
    fn react_router_does_not_flag_against_react() {
        // react-router is itself in the top-1000 list, so the exact-match rule
        // skips it before any per-pair scoring runs. This is the intended path.
        let findings = enrich(&cs_added(vec![comp("react-router")]));
        assert!(
            findings.is_empty(),
            "react-router should not be flagged, got {findings:?}"
        );
    }

    #[test]
    fn axios_retry_does_not_flag_against_axios() {
        // axios-retry is NOT in the top-1000 list but IS a well-formed
        // ecosystem extension (`<popular>-<suffix>`). The is_likely_legit_extension
        // rule must skip the axios pairing, and no other legit name should
        // score above threshold.
        let findings = enrich(&cs_added(vec![comp("axios-retry")]));
        assert!(
            findings.is_empty(),
            "axios-retry is a legit-shaped extension and must not be flagged; got {findings:?}"
        );
    }

    #[test]
    fn exact_match_is_not_flagged() {
        let findings = enrich(&cs_added(vec![comp("axios")]));
        assert!(findings.is_empty(), "exact match must not fire");
    }

    #[test]
    fn case_insensitive_exact_match_is_not_flagged() {
        // npm names are conventionally lowercase but technically case-sensitive.
        // For the typosquat signal — visual similarity to a human reader —
        // case-only-different is the same package.
        let findings = enrich(&cs_added(vec![comp("Axios")]));
        assert!(findings.is_empty());
    }

    #[test]
    fn non_npm_added_components_are_ignored() {
        let mut c = comp("crossenv");
        c.ecosystem = Ecosystem::PyPI;
        let findings = enrich(&cs_added(vec![c]));
        assert!(
            findings.is_empty(),
            "non-npm components must not be checked against the npm list"
        );
    }

    #[test]
    fn empty_changeset_yields_no_findings() {
        assert!(enrich(&ChangeSet::default()).is_empty());
    }

    #[test]
    fn findings_preserve_added_iteration_order() {
        let findings = enrich(&cs_added(vec![comp("plain-crypto-js"), comp("crossenv")]));
        assert_eq!(findings.len(), 2, "expected both to fire, got {findings:?}");
        assert_eq!(findings[0].component.name, "plain-crypto-js");
        assert_eq!(findings[0].closest, "crypto-js");
        assert_eq!(findings[1].component.name, "crossenv");
        assert_eq!(findings[1].closest, "cross-env");
    }

    #[test]
    fn likely_legit_extension_requires_separator() {
        // "expresss" starts with "express" but the next char is 's', not a
        // separator — this is a typo, not an extension. JW (~0.97) carries it
        // over the threshold.
        assert!(!is_likely_legit_extension("expresss", "express"));
        assert!(is_likely_legit_extension("express-graphql", "express"));
        assert!(is_likely_legit_extension("axios.retry", "axios"));
    }

    #[test]
    fn suffix_containment_requires_substantial_prefix() {
        // crypto-jss does NOT have crypto-js as a suffix (it ends with `s`),
        // so the suffix rule does not fire here — the JW similarity catches
        // the typo independently.
        assert!(!has_suspicious_suffix_containment(
            "crypto-jss",
            "crypto-js"
        ));
        // plain-crypto-js DOES have crypto-js as suffix with a substantial
        // 6-char prefix, well above the SUFFIX_BOOST_MIN_DELTA threshold.
        assert!(has_suspicious_suffix_containment(
            "plain-crypto-js",
            "crypto-js"
        ));
    }

    #[test]
    fn short_legit_names_skip_structural_rules() {
        // "fs" is in the top-1000 list at length 2. Both structural rules
        // require legit length ≥ MIN_LEGIT_LEN_FOR_STRUCTURAL_RULES (5) so
        // we do NOT spuriously flag arbitrary "*-fs" packages as squats of fs.
        assert!(!is_likely_legit_extension("my-fs-helper", "fs"));
        assert!(!has_suspicious_suffix_containment("super-cool-fs", "fs"));
    }
}
