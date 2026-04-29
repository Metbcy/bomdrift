//! Benchmarks for the typosquat enricher. Measures the cost of scoring a
//! candidate against the embedded npm top-1k list — the pure-compute hot
//! path that runs on every `cs.added` component in offline mode.
//!
//! Run with `cargo bench --bench typosquat`.

use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};

use bomdrift::diff::ChangeSet;
use bomdrift::enrich::typosquat;
use bomdrift::model::{Component, Ecosystem, Relationship};

fn comp(name: &str, eco: Ecosystem) -> Component {
    let purl_type = match &eco {
        Ecosystem::Npm => "npm",
        Ecosystem::PyPI => "pypi",
        Ecosystem::Cargo => "cargo",
        _ => "other",
    };
    Component {
        name: name.to_string(),
        version: "1.0.0".to_string(),
        ecosystem: eco,
        purl: Some(format!("pkg:{purl_type}/{name}@1.0.0")),
        licenses: Vec::new(),
        supplier: None,
        hashes: Vec::new(),
        relationship: Relationship::Unknown,
        source_url: None,
        bom_ref: None,
    }
}

fn cs_with(n: usize, name: &str, eco: Ecosystem) -> ChangeSet {
    let mut added = Vec::with_capacity(n);
    for _ in 0..n {
        added.push(comp(name, eco.clone()));
    }
    ChangeSet {
        added,
        ..Default::default()
    }
}

fn bench_typosquat(c: &mut Criterion) {
    let mut g = c.benchmark_group("typosquat");

    // Single-candidate path. The first call also pays the embedded-list
    // load cost (~1000 names parsed + canonicalized + interned). That
    // cost is one-shot per process; subsequent calls reuse the OnceLock.
    // Criterion's iter() lets us measure the cached path.
    let cs_one_squat = cs_with(1, "plain-crypto-js", Ecosystem::Npm);
    g.bench_function("one_npm_typosquat_axios", |b| {
        b.iter(|| {
            let findings = typosquat::enrich(black_box(&cs_one_squat));
            black_box(findings);
        });
    });

    // Larger batch: simulates a PR that adds many new deps. The work
    // scales linearly in the number of candidates × the legit-list size,
    // so this measures the per-candidate scoring cost amortized.
    for &n in &[10, 50, 100] {
        let cs = cs_with(n, "plain-crypto-js", Ecosystem::Npm);
        g.bench_with_input(BenchmarkId::new("npm_batch", n), &cs, |b, cs| {
            b.iter(|| {
                let findings = typosquat::enrich(black_box(cs));
                black_box(findings);
            });
        });
    }

    // Cross-ecosystem: single candidate per ecosystem, total 4 dispatches
    // through the per-ecosystem list-load and rules path.
    let mut mixed = ChangeSet::default();
    mixed.added.push(comp("plain-crypto-js", Ecosystem::Npm));
    mixed.added.push(comp("requessts", Ecosystem::PyPI));
    mixed.added.push(comp("serdee", Ecosystem::Cargo));
    g.bench_function("mixed_three_ecosystems", |b| {
        b.iter(|| {
            let findings = typosquat::enrich(black_box(&mixed));
            black_box(findings);
        });
    });

    g.finish();
}

criterion_group!(benches, bench_typosquat);
criterion_main!(benches);
