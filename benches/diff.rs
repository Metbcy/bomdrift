//! Benchmarks for the diff core. Measures `diff::diff(before, after)` on
//! the bundled axios-incident fixture pair (~3 components per side, the
//! shape of a typical small PR diff) and on a synthetic large pair (200
//! components per side, simulating a monorepo SBOM).
//!
//! The synthetic large pair is generated in-process to avoid committing a
//! 200-component fixture file. The shape is deterministic so the bench
//! numbers are stable across runs.
//!
//! Run with `cargo bench --bench diff`.

use std::fs;

use criterion::{Criterion, black_box, criterion_group, criterion_main};

use bomdrift::diff;
use bomdrift::model::{Component, Ecosystem, Relationship, Sbom, SbomFormat};
use bomdrift::parse;

fn load(path: &str) -> Sbom {
    let body = fs::read_to_string(path).expect("fixture must be readable");
    let v: serde_json::Value = serde_json::from_str(&body).expect("must parse JSON");
    parse::parse_with_format(v, None).expect("must normalize to Sbom")
}

fn synth_component(i: usize, version_offset: usize) -> Component {
    let name = format!("pkg-{i:04}");
    let mut version = format!("1.{}.0", i % 50);
    if i.is_multiple_of(2) {
        version = format!("1.{}.0", (i % 50) + version_offset);
    }
    let purl = format!("pkg:npm/{name}@{version}");
    Component {
        name: name.clone(),
        version,
        ecosystem: Ecosystem::Npm,
        purl: Some(purl.clone()),
        licenses: vec!["MIT".to_string()],
        supplier: None,
        hashes: Vec::new(),
        relationship: Relationship::Unknown,
        source_url: None,
        bom_ref: Some(purl),
    }
}

fn synth_sbom(n: usize, version_offset: usize) -> Sbom {
    let components = (0..n).map(|i| synth_component(i, version_offset)).collect();
    Sbom {
        format: SbomFormat::CycloneDx,
        serial: None,
        components,
    }
}

fn bench_diff(c: &mut Criterion) {
    let mut g = c.benchmark_group("diff");

    // Real fixture pair (axios incident: 3-4 components per side).
    let before = load("tests/fixtures/cdx-minimal.json");
    let after = load("tests/fixtures/cdx-after.json");
    g.bench_function("axios_fixture_pair", |b| {
        b.iter(|| {
            let cs = diff::diff(black_box(&before), black_box(&after));
            black_box(cs);
        });
    });

    // Synthetic monorepo-scale pair (200 components per side, half
    // version-changed).
    let synth_before = synth_sbom(200, 0);
    let synth_after = synth_sbom(200, 1);
    g.bench_function("synth_monorepo_200", |b| {
        b.iter(|| {
            let cs = diff::diff(black_box(&synth_before), black_box(&synth_after));
            black_box(cs);
        });
    });

    // Self-diff (no changes): exercises every key through the BTreeMap
    // intersection without producing any add/remove/version_changed work.
    g.bench_function("synth_self_diff_200", |b| {
        b.iter(|| {
            let cs = diff::diff(black_box(&synth_before), black_box(&synth_before));
            black_box(cs);
        });
    });

    g.finish();
}

criterion_group!(benches, bench_diff);
criterion_main!(benches);
