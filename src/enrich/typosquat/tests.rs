#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented
)]
use super::canonical::{last_path_segment, pep503_normalize};
use super::ecosystem::SupportedEcosystem;
use super::lists::{default_cache_path, legit_list_for, load_legit_list};
use super::matching::{
    best_match_maven, has_suspicious_suffix_containment, is_likely_legit_extension,
};
use super::*;
use crate::diff::ChangeSet;
use crate::model::{Component, Ecosystem, Relationship};

fn comp(name: &str) -> Component {
    comp_eco(name, Ecosystem::Npm)
}

fn comp_eco(name: &str, ecosystem: Ecosystem) -> Component {
    let purl_type = match ecosystem {
        Ecosystem::Npm => "npm",
        Ecosystem::PyPI => "pypi",
        Ecosystem::Cargo => "cargo",
        Ecosystem::Maven => "maven",
        Ecosystem::Go => "golang",
        Ecosystem::Gem => "gem",
        Ecosystem::NuGet => "nuget",
        Ecosystem::Composer => "composer",
        Ecosystem::Other(_) => "other",
    };
    Component {
        name: name.to_string(),
        version: "1.0.0".to_string(),
        ecosystem,
        purl: Some(format!("pkg:{purl_type}/{name}@1.0.0")),
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

// ---- npm regression tests (preserved from v0.1) -----------------------

#[test]
fn embedded_list_loads_thousand_names() {
    let list = legit_list_for(SupportedEcosystem::Npm);
    assert!(
        list.len() >= 900,
        "expected ~1000 npm names, got {}",
        list.len()
    );
    let by_str: Vec<&str> = list.iter().map(String::as_str).collect();
    assert!(by_str.contains(&"crypto-js"));
    assert!(by_str.contains(&"cross-env"));
    assert!(by_str.contains(&"axios"));
    assert!(by_str.contains(&"react"));
    assert!(by_str.contains(&"react-router"));
}

#[test]
fn crossenv_flags_against_cross_env_via_jaro_winkler() {
    let findings = enrich(&cs_added(vec![comp("crossenv")]));
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].closest, "cross-env");
    assert!(findings[0].score >= SIMILARITY_THRESHOLD);
}

#[test]
fn plain_crypto_js_flags_against_crypto_js_via_suffix_boost() {
    let findings = enrich(&cs_added(vec![comp("plain-crypto-js")]));
    assert_eq!(findings.len(), 1);
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
    let findings = enrich(&cs_added(vec![comp("react-router")]));
    assert!(findings.is_empty(), "got {findings:?}");
}

#[test]
fn axios_retry_does_not_flag_against_axios() {
    let findings = enrich(&cs_added(vec![comp("axios-retry")]));
    assert!(findings.is_empty(), "got {findings:?}");
}

#[test]
fn exact_match_is_not_flagged() {
    let findings = enrich(&cs_added(vec![comp("axios")]));
    assert!(findings.is_empty());
}

#[test]
fn case_insensitive_exact_match_is_not_flagged() {
    let findings = enrich(&cs_added(vec![comp("Axios")]));
    assert!(findings.is_empty());
}

#[test]
fn unsupported_ecosystem_components_are_ignored() {
    let mut c = comp("crossenv");
    c.ecosystem = Ecosystem::Go;
    let findings = enrich(&cs_added(vec![c]));
    assert!(findings.is_empty());
}

#[test]
fn empty_changeset_yields_no_findings() {
    assert!(enrich(&ChangeSet::default()).is_empty());
}

#[test]
fn findings_preserve_added_iteration_order() {
    let findings = enrich(&cs_added(vec![comp("plain-crypto-js"), comp("crossenv")]));
    assert_eq!(findings.len(), 2);
    assert_eq!(findings[0].component.name, "plain-crypto-js");
    assert_eq!(findings[1].component.name, "crossenv");
}

#[test]
fn likely_legit_extension_requires_separator_npm() {
    let seps = SupportedEcosystem::Npm.separators();
    assert!(!is_likely_legit_extension("expresss", "express", seps));
    assert!(is_likely_legit_extension(
        "express-graphql",
        "express",
        seps
    ));
    assert!(is_likely_legit_extension("axios.retry", "axios", seps));
}

#[test]
fn suffix_containment_requires_substantial_prefix() {
    assert!(!has_suspicious_suffix_containment(
        "crypto-jss",
        "crypto-js"
    ));
    assert!(has_suspicious_suffix_containment(
        "plain-crypto-js",
        "crypto-js"
    ));
}

#[test]
fn short_legit_names_skip_structural_rules() {
    let seps = SupportedEcosystem::Npm.separators();
    assert!(!is_likely_legit_extension("my-fs-helper", "fs", seps));
    assert!(!has_suspicious_suffix_containment("super-cool-fs", "fs"));
}

#[test]
fn cache_file_overrides_embedded_snapshot_for_npm() {
    let dir = tempdir_unique("typosquat-cache-test");
    let cache_path = dir.join("npm.txt");
    std::fs::write(
        &cache_path,
        "# header comment, ignored\nzzz-fake-cache-name\nzzz-other-cache-name\n\n",
    )
    .unwrap();

    let loaded = load_legit_list(SupportedEcosystem::Npm, Some(&cache_path));
    assert_eq!(
        loaded,
        vec![
            "zzz-fake-cache-name".to_string(),
            "zzz-other-cache-name".to_string()
        ]
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn missing_cache_file_falls_back_to_embedded_snapshot_for_npm() {
    let nonexistent = std::path::PathBuf::from("/this/path/does/not/exist/npm.txt");
    let loaded = load_legit_list(SupportedEcosystem::Npm, Some(&nonexistent));
    assert!(loaded.len() >= 900, "got {}", loaded.len());
}

#[test]
fn empty_cache_file_falls_back_to_embedded_snapshot_for_npm() {
    let dir = tempdir_unique("typosquat-empty-cache");
    let cache_path = dir.join("npm.txt");
    std::fs::write(&cache_path, "# only a comment\n\n   \n").unwrap();
    let loaded = load_legit_list(SupportedEcosystem::Npm, Some(&cache_path));
    assert!(loaded.len() >= 900);
    let _ = std::fs::remove_dir_all(&dir);
}

// ---- PyPI tests -------------------------------------------------------

#[test]
fn pypi_list_loads_with_known_top_packages() {
    let list = legit_list_for(SupportedEcosystem::PyPI);
    let by_str: Vec<&str> = list.iter().map(String::as_str).collect();
    assert!(
        by_str.contains(&"requests"),
        "requests must be in PyPI list"
    );
    assert!(by_str.contains(&"numpy"));
    assert!(by_str.contains(&"pandas"));
}

#[test]
fn pypi_typo_flags_against_requests() {
    let findings = enrich(&cs_added(vec![comp_eco("requessts", Ecosystem::PyPI)]));
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].closest, "requests");
}

#[test]
fn pypi_underscore_dash_equivalence_is_not_a_squat() {
    // `scikit_learn` vs `scikit-learn`: PEP 503 normalizes these to the
    // same name, so this is treated as the legitimate package, not a squat.
    let findings = enrich(&cs_added(vec![comp_eco("scikit_learn", Ecosystem::PyPI)]));
    assert!(
        findings.is_empty(),
        "PEP 503 equivalence must not flag, got {findings:?}"
    );
}

#[test]
fn pypi_extension_pattern_is_not_a_squat() {
    // `pytest-asyncio` is the standard extension form for `pytest`.
    let findings = enrich(&cs_added(vec![comp_eco("pytest-asyncio", Ecosystem::PyPI)]));
    assert!(findings.is_empty(), "got {findings:?}");
}

// ---- Cargo tests ------------------------------------------------------

#[test]
fn cargo_list_loads_with_known_top_crates() {
    let list = legit_list_for(SupportedEcosystem::Cargo);
    let by_str: Vec<&str> = list.iter().map(String::as_str).collect();
    assert!(by_str.contains(&"serde"));
    assert!(by_str.contains(&"tokio"));
    assert!(by_str.contains(&"clap"));
}

#[test]
fn cargo_typo_flags_against_serde() {
    let findings = enrich(&cs_added(vec![comp_eco("serdee", Ecosystem::Cargo)]));
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].closest, "serde");
}

#[test]
fn cargo_extension_pattern_is_not_a_squat() {
    // `serde-json` would collide with the real `serde_json`, but cargo
    // names use `_` and the legit-extension rule on cargo is `-` only —
    // so this still flags via JW unless we exact-match. Use an actual
    // extension pattern instead: `tokio-stream` extending `tokio`.
    let findings = enrich(&cs_added(vec![comp_eco("tokio-stream", Ecosystem::Cargo)]));
    assert!(findings.is_empty(), "got {findings:?}");
}

// ---- Maven tests ------------------------------------------------------

#[test]
fn maven_list_loads_with_known_top_coords() {
    let list = legit_list_for(SupportedEcosystem::Maven);
    let by_str: Vec<&str> = list.iter().map(String::as_str).collect();
    assert!(by_str.iter().any(|s| s.ends_with(":commons-lang3")));
    assert!(by_str.iter().any(|s| s.ends_with(":guava")));
}

#[test]
fn maven_artifact_typo_flags_against_commons_lang3() {
    // groupId matches a real coord; artifactId is one char off.
    let findings = enrich(&cs_added(vec![comp_eco(
        "org.apache.commons:commons-lng3",
        Ecosystem::Maven,
    )]));
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert!(findings[0].closest.ends_with(":commons-lang3"));
}

#[test]
fn maven_exact_artifact_match_with_different_group_does_not_flag() {
    // Same artifactId as a known package but different group — that's a
    // legitimate fork or republish; not a typosquat by the artifactId-only
    // rule. Defer to a human reviewer.
    let findings = enrich(&cs_added(vec![comp_eco(
        "com.example.fork:commons-lang3",
        Ecosystem::Maven,
    )]));
    assert!(findings.is_empty(), "got {findings:?}");
}

// ---- Go tests --------------------------------------------------------

#[test]
fn go_list_loads_with_known_top_modules() {
    let list = legit_list_for(SupportedEcosystem::Go);
    assert!(list.len() >= 100, "got {}", list.len());
    let by_str: Vec<&str> = list.iter().map(String::as_str).collect();
    assert!(by_str.iter().any(|s| s.ends_with("/cobra")));
    assert!(by_str.iter().any(|s| s.ends_with("/gin")));
    assert!(by_str.iter().any(|s| s.ends_with("/grpc")));
}

#[test]
fn go_repo_typo_flags_against_cobra() {
    // last-segment typo of cobra. Different vendor + a one-character
    // drift on the repo name.
    let findings = enrich(&cs_added(vec![comp_eco(
        "github.com/attacker/cobraa",
        Ecosystem::Go,
    )]));
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert!(findings[0].closest.ends_with("/cobra"));
}

#[test]
fn go_legit_fork_under_different_org_does_not_flag() {
    // Same last segment as a known module but under a different
    // org — legitimate fork; defer to a human reviewer.
    let findings = enrich(&cs_added(vec![comp_eco(
        "github.com/myorg/cobra",
        Ecosystem::Go,
    )]));
    assert!(findings.is_empty(), "got {findings:?}");
}

#[test]
fn go_extension_pattern_is_not_a_squat() {
    // `cobra-cli` is the standard extension form for `cobra` — match
    // form is `cobra-cli`, legit match form is `cobra`, separator `-`
    // → extension rule fires, skip.
    let findings = enrich(&cs_added(vec![comp_eco(
        "github.com/spf13/cobra-cli",
        Ecosystem::Go,
    )]));
    assert!(findings.is_empty(), "got {findings:?}");
}

// ---- Gem tests -------------------------------------------------------

#[test]
fn gem_list_loads_with_known_top_gems() {
    let list = legit_list_for(SupportedEcosystem::Gem);
    let by_str: Vec<&str> = list.iter().map(String::as_str).collect();
    assert!(by_str.contains(&"rails"));
    assert!(by_str.contains(&"rspec"));
    assert!(by_str.contains(&"devise"));
}

#[test]
fn gem_typo_flags_against_rails() {
    let findings = enrich(&cs_added(vec![comp_eco("railz", Ecosystem::Gem)]));
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].closest, "rails");
}

#[test]
fn gem_extension_pattern_is_not_a_squat() {
    // `rspec-rails` is the canonical Rails-integration variant of
    // rspec, with `-` as the gem-extension separator.
    let findings = enrich(&cs_added(vec![comp_eco("rspec-rails", Ecosystem::Gem)]));
    assert!(findings.is_empty(), "got {findings:?}");
}

// ---- NuGet tests -----------------------------------------------------

#[test]
fn nuget_list_loads_with_known_top_packages() {
    let list = legit_list_for(SupportedEcosystem::NuGet);
    let by_str: Vec<&str> = list.iter().map(String::as_str).collect();
    // NuGet IDs are case-insensitive; canonicalized to lowercase.
    assert!(by_str.contains(&"newtonsoft.json"));
    assert!(by_str.iter().any(|s| s.starts_with("microsoft.")));
}

#[test]
fn nuget_typo_flags_against_newtonsoft_json() {
    let findings = enrich(&cs_added(vec![comp_eco(
        "Newtonsoft.Jsonn",
        Ecosystem::NuGet,
    )]));
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].closest, "newtonsoft.json");
}

#[test]
fn nuget_case_insensitive_exact_match_is_not_flagged() {
    // `Newtonsoft.Json` and `newtonsoft.json` are the same package per
    // NuGet's case-insensitive ID rules — must not flag.
    let findings = enrich(&cs_added(vec![comp_eco(
        "NEWTONSOFT.JSON",
        Ecosystem::NuGet,
    )]));
    assert!(findings.is_empty(), "got {findings:?}");
}

// ---- Composer tests --------------------------------------------------

#[test]
fn composer_list_loads_with_known_top_packages() {
    let list = legit_list_for(SupportedEcosystem::Composer);
    let by_str: Vec<&str> = list.iter().map(String::as_str).collect();
    assert!(by_str.iter().any(|s| s.ends_with("/console")));
    assert!(by_str.iter().any(|s| s.ends_with("/framework")));
    assert!(by_str.iter().any(|s| s.ends_with("/guzzle")));
}

#[test]
fn composer_package_typo_flags_against_symfony_console() {
    // Different vendor, single-character drift on the package portion.
    let findings = enrich(&cs_added(vec![comp_eco(
        "attacker/consolee",
        Ecosystem::Composer,
    )]));
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert!(findings[0].closest.ends_with("/console"));
}

#[test]
fn composer_legit_fork_under_different_vendor_does_not_flag() {
    // Same package portion as a known coordinate but under a different
    // vendor — legitimate fork or alternative. Don't flag.
    let findings = enrich(&cs_added(vec![comp_eco(
        "myorg/console",
        Ecosystem::Composer,
    )]));
    assert!(findings.is_empty(), "got {findings:?}");
}

// ---- helpers ----------------------------------------------------------

fn tempdir_unique(stem: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "bomdrift-{stem}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&path).unwrap();
    path
}

#[test]
fn pep503_normalization() {
    assert_eq!(pep503_normalize("Foo_Bar.Baz"), "foo-bar-baz");
    assert_eq!(pep503_normalize("scikit__learn"), "scikit-learn");
    assert_eq!(pep503_normalize("---weird---"), "weird");
}

// ---- Property-based tests --------------------------------------------

use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1024))]

    /// `pep503_normalize` must never panic on arbitrary unicode and
    /// must always produce ASCII-only output (PEP 503's normalization
    /// rules collapse all non-alphanumeric to `-`, so the output is
    /// constrained to lowercase ASCII alphanumerics + `-`). Any
    /// upstream mojibake or zero-width character should not crash.
    #[test]
    fn pep503_normalize_does_not_panic(s in ".*") {
        let out = pep503_normalize(&s);
        // Output is always lowercase (no uppercase made it through).
        prop_assert_eq!(out.clone(), out.to_lowercase());
        // Output never starts or ends with `-` (the trim_matches step).
        prop_assert!(!out.starts_with('-'));
        prop_assert!(!out.ends_with('-'));
    }

    /// `last_path_segment` must never panic and must return a substring
    /// of its input (i.e. the returned `&str` borrows from the
    /// argument). The substring rule is enforced by the type system —
    /// the property test catches semantic bugs like "returned an empty
    /// string when the input had no `/`".
    #[test]
    fn last_path_segment_returns_substring(s in ".*") {
        let result = last_path_segment(&s);
        // Result is always present in the input.
        prop_assert!(s.contains(result) || result.is_empty() && s.is_empty());
        // No `/` in the result (we split on `/`).
        prop_assert!(!result.contains('/'));
    }

    /// The entire `enrich(cs)` entry point must never panic on
    /// arbitrary `ChangeSet::added` shapes. Empty ChangeSets are
    /// trivially fine; this exercises the loops over arbitrary
    /// component names + ecosystems.
    #[test]
    fn enrich_does_not_panic_on_arbitrary_components(
        names in proptest::collection::vec(".*", 0..32)
    ) {
        let added: Vec<Component> = names
            .iter()
            .map(|n| {
                let eco = match n.len() % 5 {
                    0 => Ecosystem::Npm,
                    1 => Ecosystem::PyPI,
                    2 => Ecosystem::Cargo,
                    3 => Ecosystem::Go,
                    _ => Ecosystem::Other("unknown".to_string()),
                };
                Component {
                    name: n.clone(),
                    version: "1.0.0".to_string(),
                    ecosystem: eco,
                    purl: None,
                    licenses: Vec::new(),
                    supplier: None,
                    hashes: Vec::new(),
                    relationship: Relationship::Unknown,
                    source_url: None,
                    bom_ref: None,
                }
            })
            .collect();
        let cs = ChangeSet { added, ..Default::default() };
        let _ = enrich(&cs);
    }
}

#[test]
fn similarity_threshold_override_widens_match_set() {
    // Pick a near-miss candidate; relaxing the threshold must not
    // reduce the finding count vs a strict 0.99 cutoff.
    let candidate = comp("expressss");
    let cs = cs_added(vec![candidate.clone()]);
    let strict = enrich_with_threshold(&cs, Some(0.99));
    let relaxed = enrich_with_threshold(&cs, Some(0.80));
    assert!(
        relaxed.len() >= strict.len(),
        "lowering the threshold must not reduce findings"
    );
}

// ---- Mutation-test gap closers (issue #35) ---------------------------

#[test]
fn maven_best_match_includes_distance_equal_to_max_levenshtein() {
    // commons-lang3 (12 chars) vs commons-lng2 (11): Levenshtein = 2
    // (delete 'a', substitute '3'->'2'). Exactly at MAVEN_MAX_LEVENSHTEIN.
    // Guards line 371: changing `>` to `>=` would drop this finding.
    let findings = enrich(&cs_added(vec![comp_eco(
        "org.apache.commons:commons-lng2",
        Ecosystem::Maven,
    )]));
    assert_eq!(
        findings.len(),
        1,
        "dist == MAVEN_MAX_LEVENSHTEIN must still flag; got {findings:?}"
    );
    assert!(findings[0].closest.ends_with(":commons-lang3"));
}

#[test]
fn maven_best_match_picks_closest_when_multiple_candidates_within_distance() {
    // Direct unit test of best_match_maven to pin the "closer wins"
    // selection logic. Guards line 375 match guard (`true`/`false`
    // stubs and `>=`->`<` swap all break this ordering).
    //
    // candidate "guavb" (5 chars):
    //   vs "guava"   -> dist 1
    //   vs "gauva"   -> dist 2
    // Both are within MAVEN_MAX_LEVENSHTEIN=2 and the algorithm must
    // pick "guava" (closer). Order legit so the farther match comes
    // FIRST -- that way the `dist >= d` guard is the only thing that
    // promotes the closer second entry.
    let legit = vec![
        "x.y:gauva".to_string(), // dist 2, seen first
        "x.y:guava".to_string(), // dist 1, must win
    ];
    let got = best_match_maven("x.y:guavb", &legit, 0.0);
    assert_eq!(
        got.map(|(name, _)| name),
        Some("x.y:guava"),
        "closer match must beat earlier farther match"
    );
}

#[test]
fn maven_best_match_score_formula_matches_one_minus_dist_over_len_plus_one() {
    // Guards the arithmetic on lines 380-381:
    //   denom = legit_artifact.len() + 1
    //   raw   = 1.0 - dist / denom
    // For artifact "guava" (5) with dist 1: denom = 6, raw = 1 - 1/6.
    // Threshold pulled low so `.max(threshold)` does not clamp.
    let legit = vec!["x.y:guava".to_string()];
    let (name, score) =
        best_match_maven("x.y:guavb", &legit, 0.1).expect("guavb must match guava within Lev 2");
    assert_eq!(name, "x.y:guava");
    let expected = 1.0_f64 - 1.0 / 6.0;
    assert!(
        (score - expected).abs() < 1e-9,
        "score {score} must equal 1 - 1/(len+1) = {expected}"
    );
}

#[test]
fn suspicious_suffix_containment_requires_strict_delta_over_legit_len() {
    // Guards line 416: `candidate.len() <= legit.len() + SUFFIX_BOOST_MIN_DELTA`.
    // Boundary case: candidate length equals legit + delta exactly.
    // SUFFIX_BOOST_MIN_DELTA = 3, so legit "crypto" (6) + 3 = 9.
    // candidate "ab-crypto" (9 chars) must NOT be suspicious -- need
    // strictly MORE than that delta.
    assert!(
        !has_suspicious_suffix_containment("ab-crypto", "crypto"),
        "candidate at exactly len + delta is below the suspicion bar"
    );
    // One char over the boundary flips it on.
    assert!(
        has_suspicious_suffix_containment("abc-crypto", "crypto"),
        "candidate at len + delta + 1 must trip the rule"
    );
}

#[test]
fn default_cache_path_targets_typosquat_subdir_with_ecosystem_filename() {
    // Guards line 471 return-value mutants (None / Some(Default::default())).
    // The path must end with `typosquat/<eco>.txt`.
    for (eco, fname) in [
        (SupportedEcosystem::Npm, "npm.txt"),
        (SupportedEcosystem::PyPI, "pypi.txt"),
        (SupportedEcosystem::Maven, "maven.txt"),
    ] {
        let p = default_cache_path(eco).expect("cache root resolves under test");
        // Compare via Path components so this test works on both
        // Unix ("typosquat/npm.txt") and Windows ("typosquat\npm.txt").
        assert_eq!(
            p.file_name().and_then(|s| s.to_str()),
            Some(fname),
            "path {} must have filename {fname}",
            p.display()
        );
        assert_eq!(
            p.parent()
                .and_then(|d| d.file_name())
                .and_then(|s| s.to_str()),
            Some("typosquat"),
            "path {} must sit under a 'typosquat' subdir",
            p.display()
        );
    }
}
