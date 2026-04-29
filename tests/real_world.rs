//! Regression tests against real-world SBOMs from public corpora.
//!
//! These exercise the parser, diff core, and renderers on documents that
//! weren't constructed by the bomdrift authors — catching parse-shape
//! regressions, edge-case JSON structures, and behavior on document sizes
//! that the small fixtures don't reach.
//!
//! Sources
//!
//! - `*.cdx.json`: <https://github.com/CycloneDX/sbom-examples>
//! - `*.spdx.json`: <https://github.com/spdx/spdx-examples>
//!
//! All fixtures are committed verbatim; no transformation. To refresh the
//! corpus, re-fetch from the upstream repos. The corpus is intentionally
//! small (~2.7 MB total) so test runtime stays sub-second.

use std::fs;
use std::path::PathBuf;

use bomdrift::diff;
use bomdrift::model::{Ecosystem, Sbom, SbomFormat};
use bomdrift::parse;
use bomdrift::render;

fn fixture(path: &str) -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests/fixtures/real-world");
    p.push(path);
    p
}

fn parse_fixture(path: &str) -> Sbom {
    let body = fs::read_to_string(fixture(path)).expect("fixture must be readable");
    let v: serde_json::Value = serde_json::from_str(&body).expect("fixture must be valid JSON");
    parse::parse_with_format(v, None).expect("fixture must parse to Sbom")
}

const CDX_FIXTURES: &[&str] = &[
    "cern-lhc-vdm-editor-e564943.cdx.json",
    "dropwizard-1.3.15.cdx.json",
    "keycloak-10.0.2.cdx.json",
    "laravel-7.12.0.cdx.json",
];

const SPDX_FIXTURES: &[&str] = &["spdx-example10.spdx.json"];

#[test]
fn every_real_world_cdx_fixture_parses_with_components() {
    for path in CDX_FIXTURES {
        let sbom = parse_fixture(path);
        assert_eq!(
            sbom.format,
            SbomFormat::CycloneDx,
            "fixture {path} should auto-detect as CycloneDX"
        );
        assert!(
            !sbom.components.is_empty(),
            "fixture {path} parsed to zero components — likely a parser regression"
        );
    }
}

#[test]
fn every_real_world_spdx_fixture_parses_with_components() {
    for path in SPDX_FIXTURES {
        let sbom = parse_fixture(path);
        assert_eq!(
            sbom.format,
            SbomFormat::Spdx,
            "fixture {path} should auto-detect as SPDX"
        );
        assert!(
            !sbom.components.is_empty(),
            "fixture {path} parsed to zero components"
        );
    }
}

#[test]
fn real_world_fixtures_contain_no_file_pseudo_components_after_filter() {
    // Syft's directory cataloger emits each scanned YAML/lockfile as a
    // synthetic Ecosystem::Other("file") component. The bundled CDX/SPDX
    // fixtures from upstream corpora don't trip this cataloger (they're
    // static documents, not directory scans), so the assertion is trivially
    // true on today's corpus — but it acts as a regression guard if the
    // corpus is ever refreshed from a Syft-produced source.
    for path in CDX_FIXTURES.iter().chain(SPDX_FIXTURES) {
        let mut sbom = parse_fixture(path);
        parse::filter_file_components(&mut sbom);
        for comp in &sbom.components {
            if let Ecosystem::Other(s) = &comp.ecosystem {
                assert_ne!(
                    s, "file",
                    "fixture {path}: file: pseudo-component {} survived filter_file_components",
                    comp.name
                );
            }
        }
    }
}

#[test]
fn known_purl_types_resolve_to_canonical_ecosystem() {
    // Components whose purl is `pkg:npm/...`, `pkg:pypi/...`, etc. should
    // resolve to the canonical Ecosystem variant — never to
    // Ecosystem::Other(_) for a known type. A regression here would
    // indicate ecosystem_from_purl missed a match arm.
    for path in CDX_FIXTURES.iter().chain(SPDX_FIXTURES) {
        let sbom = parse_fixture(path);
        for comp in &sbom.components {
            let Some(purl) = &comp.purl else { continue };
            let known_prefix = [
                "pkg:npm/",
                "pkg:pypi/",
                "pkg:cargo/",
                "pkg:maven/",
                "pkg:golang/",
                "pkg:gem/",
                "pkg:nuget/",
                "pkg:composer/",
            ];
            for prefix in known_prefix {
                if purl.starts_with(prefix) {
                    assert!(
                        !matches!(comp.ecosystem, Ecosystem::Other(_)),
                        "fixture {path}: component with purl {purl} resolved to Ecosystem::Other(_) instead of the canonical variant"
                    );
                }
            }
        }
    }
}

#[test]
fn diff_two_unrelated_real_world_sboms_does_not_panic() {
    // The dropwizard and laravel SBOMs share zero packages but exercise
    // the BTreeMap-based ChangeSet construction at realistic scale (a few
    // thousand components combined). Exit-code-of-success here is the
    // "no panic on real-world keys" guarantee.
    let dropwizard = parse_fixture("dropwizard-1.3.15.cdx.json");
    let laravel = parse_fixture("laravel-7.12.0.cdx.json");

    let cs = diff::diff(&dropwizard, &laravel);
    // Both sides have unique components, so every component appears in
    // either added or removed.
    assert!(!cs.added.is_empty());
    assert!(!cs.removed.is_empty());
}

#[test]
fn render_diff_of_real_world_sboms_to_all_formats() {
    // Smoke test: full pipeline (parse -> diff -> render) on a
    // realistic SBOM pair must produce non-empty output for every
    // renderer. Catches renderer regressions that the small fixtures
    // miss because they don't exercise the CycloneDX feature surface
    // (external references, deeply nested licenses, etc.).
    let before = parse_fixture("dropwizard-1.3.15.cdx.json");
    let after = parse_fixture("keycloak-10.0.2.cdx.json");

    let cs = diff::diff(&before, &after);
    let enrichment = bomdrift::enrich::Enrichment::default();

    let md = render::markdown::render(&cs, &enrichment);
    assert!(
        md.contains("## SBOM diff"),
        "markdown render must start with the canonical heading"
    );
    assert!(
        md.len() > 100,
        "markdown render must produce substantive output"
    );

    let json = render::json::render(&cs, &enrichment);
    let _: serde_json::Value =
        serde_json::from_str(&json).expect("json render must round-trip through serde_json");

    let sarif = render::sarif::render(&cs, &enrichment);
    let v: serde_json::Value =
        serde_json::from_str(&sarif).expect("sarif render must be valid JSON");
    assert_eq!(v["version"], "2.1.0", "sarif version field must be present");

    let term = render::term::render(&cs, &enrichment);
    assert!(
        term.len() > 100,
        "terminal render must produce substantive output"
    );
}

#[test]
fn self_diff_of_each_real_world_sbom_is_empty() {
    // diff(a, a) === empty. This is a strong invariant covered by the
    // proptests on synthetic data, but worth validating against real
    // fixtures too — a parser non-determinism (like HashMap-ordered
    // license sets that happen to differ between two parses of the same
    // file) would break this and not be caught by synthetic tests.
    for path in CDX_FIXTURES.iter().chain(SPDX_FIXTURES) {
        let sbom = parse_fixture(path);
        let cs = diff::diff(&sbom, &sbom);
        assert!(
            cs.is_empty(),
            "self-diff of {path} produced non-empty changeset (parser non-determinism?)"
        );
    }
}
