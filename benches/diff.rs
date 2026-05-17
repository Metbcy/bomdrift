//! Benchmarks for the diff core. Closes #29.
//!
//! The diff core (`src/diff/`) is on the critical path for every bomdrift
//! run, so we want a perf-regression catcher for any change that touches it.
//! This bench measures `diff::diff(before, after)` across three input shapes
//! (small / mid / large) and three diff workloads per shape:
//!
//! - **end_to_end**: realistic mix of added / removed / version_changed /
//!   license_changed — the production hot path.
//! - **self_diff**: identical inputs, exercises the BTreeMap construction and
//!   per-key traversal without producing any change pairs. Isolates the cost
//!   of `group_by_key` + iteration.
//! - **all_license_changed**: every key intersects, every intersecting pair
//!   has a different license set. Isolates the license-comparison branch in
//!   `diff_one_key`.
//!
//! Input sizes mirror real-world bomdrift workloads:
//!
//! - **small**: 500 components per side (typical mid-sized JS app).
//! - **large**: 5000 components per side (typical large monorepo).
//! - **stress**: 20_000 components per side (upper-bound stress, gated behind
//!   the `bench-stress` cargo feature so the default run stays under 30s).
//!
//! Run with `cargo bench --bench diff`.
//! Run with stress group: `cargo bench --bench diff --features bench-stress`.

use std::fs;

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};

use bomdrift::diff;
use bomdrift::model::{Component, Ecosystem, Relationship, Sbom, SbomFormat};
use bomdrift::parse;

fn load(path: &str) -> Sbom {
    let body = fs::read_to_string(path).expect("fixture must be readable");
    let v: serde_json::Value = serde_json::from_str(&body).expect("must parse JSON");
    parse::parse_with_format(v, None).expect("must normalize to Sbom")
}

/// Build one synthetic component. Deterministic — given `i` and `licenses`,
/// the output is byte-identical across runs so bench medians stay stable.
fn synth_component(i: usize, version: &str, licenses: Vec<String>) -> Component {
    let name = format!("pkg-{i:06}");
    let purl = format!("pkg:npm/{name}@{version}");
    Component {
        name,
        version: version.to_string(),
        ecosystem: Ecosystem::Npm,
        purl: Some(purl.clone()),
        licenses,
        supplier: None,
        hashes: Vec::new(),
        relationship: Relationship::Unknown,
        source_url: None,
        bom_ref: Some(purl),
    }
}

/// Build a baseline SBOM of `n` components, all at version 1.0.0, all MIT.
fn synth_sbom(n: usize) -> Sbom {
    let components = (0..n)
        .map(|i| synth_component(i, "1.0.0", vec!["MIT".to_string()]))
        .collect();
    Sbom {
        format: SbomFormat::CycloneDx,
        serial: None,
        components,
    }
}

/// Build the realistic-mix `after` SBOM for the **end_to_end** workload:
///
/// - 80% of keys: same version, same license (no change — the common case).
/// - 10%: version bumped (`version_changed`).
/// - 5%: license changed in place (`license_changed`).
/// - 5%: new keys not present in `before` (`added`); these replace removed
///   tail keys so the size stays `n`. The removed-side count for the diff
///   is the symmetric `before` tail.
fn synth_after_mixed(n: usize) -> Sbom {
    let components = (0..n)
        .map(|i| match i % 20 {
            // 5% version-changed (i % 20 in {0})
            0 => synth_component(i, "1.0.1", vec!["MIT".to_string()]),
            // 5% another version-changed slice (10% total)
            10 => synth_component(i, "2.0.0", vec!["MIT".to_string()]),
            // 5% license-changed in place
            1 => synth_component(i, "1.0.0", vec!["Apache-2.0".to_string()]),
            // 5% new keys (use a disjoint index range so they don't collide)
            2 => synth_component(n + i, "1.0.0", vec!["MIT".to_string()]),
            // 80% unchanged
            _ => synth_component(i, "1.0.0", vec!["MIT".to_string()]),
        })
        .collect();
    Sbom {
        format: SbomFormat::CycloneDx,
        serial: None,
        components,
    }
}

/// Build an `after` SBOM where every key intersects with `before` at the same
/// version but with a different license — isolates the license-comparison
/// branch in `diff_one_key`.
fn synth_after_all_license_changed(n: usize) -> Sbom {
    let components = (0..n)
        .map(|i| synth_component(i, "1.0.0", vec!["Apache-2.0".to_string()]))
        .collect();
    Sbom {
        format: SbomFormat::CycloneDx,
        serial: None,
        components,
    }
}

fn bench_diff(c: &mut Criterion) {
    // Real fixture pair (axios incident: 3-4 components per side). Kept from
    // the original bench as a smoke check that the bench harness still wires
    // through the real parse → diff path, not just synthetic data.
    let fixture_before = load("tests/fixtures/cdx-minimal.json");
    let fixture_after = load("tests/fixtures/cdx-after.json");
    c.bench_function("diff_axios_fixture_pair", |b| {
        b.iter(|| {
            let cs = diff::diff(black_box(&fixture_before), black_box(&fixture_after));
            black_box(cs);
        });
    });

    // Synthetic sizes. `bench-stress` adds the 20_000-component group; the
    // default set targets the "under 30s total" acceptance criterion.
    let mut sizes: Vec<usize> = vec![500, 5_000];
    if cfg!(feature = "bench-stress") {
        sizes.push(20_000);
    }

    let mut g = c.benchmark_group("diff_synth");
    for &n in &sizes {
        // Throughput is reported in components/sec, summed across both sides
        // of the diff. Lets reviewers see whether a change is a per-component
        // hit or a structural one when the numbers cross sizes.
        g.throughput(Throughput::Elements((n as u64) * 2));

        let before = synth_sbom(n);
        let after_mixed = synth_after_mixed(n);
        let after_all_lic = synth_after_all_license_changed(n);

        // end_to_end: realistic mix of all four change kinds.
        g.bench_with_input(BenchmarkId::new("end_to_end", n), &n, |b, _| {
            b.iter(|| {
                let cs = diff::diff(black_box(&before), black_box(&after_mixed));
                black_box(cs);
            });
        });

        // self_diff: identical inputs. Isolates the BTreeMap construction
        // (`group_by_key`) + per-key traversal cost with no change pairs
        // produced. This is the lower bound on diff cost for a given size.
        g.bench_with_input(BenchmarkId::new("self_diff", n), &n, |b, _| {
            b.iter(|| {
                let cs = diff::diff(black_box(&before), black_box(&before));
                black_box(cs);
            });
        });

        // all_license_changed: every intersecting pair has a different
        // license set. Isolates the license-comparison branch in
        // `diff_one_key` (the version-intersection scan that routes pairs
        // to `license_changed`).
        g.bench_with_input(BenchmarkId::new("all_license_changed", n), &n, |b, _| {
            b.iter(|| {
                let cs = diff::diff(black_box(&before), black_box(&after_all_lic));
                black_box(cs);
            });
        });
    }
    g.finish();
}

criterion_group!(benches, bench_diff);
criterion_main!(benches);
