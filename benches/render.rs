//! Benchmarks for each output renderer. Measures the cost of producing
//! markdown / JSON / SARIF / terminal output from a populated ChangeSet
//! + Enrichment graph.
//!
//! The synthetic ChangeSet is shaped like a moderately-large PR diff:
//! 50 added components, 20 removed, 30 version-changed, 5 license-changed,
//! plus 10 typosquat findings and a sprinkle of CVEs. Realistic enough to
//! catch regressions without dominating the bench runtime.
//!
//! Run with `cargo bench --bench render`.

use std::collections::HashMap;

use criterion::{Criterion, black_box, criterion_group, criterion_main};

use bomdrift::diff::ChangeSet;
use bomdrift::enrich::typosquat::TyposquatFinding;
use bomdrift::enrich::{Enrichment, Severity, VulnRef};
use bomdrift::model::{Component, Ecosystem, Relationship};
use bomdrift::render::{json, markdown, sarif, term};

fn comp(name: &str, version: &str) -> Component {
    Component {
        name: name.to_string(),
        version: version.to_string(),
        ecosystem: Ecosystem::Npm,
        purl: Some(format!("pkg:npm/{name}@{version}")),
        licenses: vec!["MIT".to_string()],
        supplier: None,
        hashes: Vec::new(),
        relationship: Relationship::Unknown,
        source_url: None,
        bom_ref: None,
    }
}

fn synth_changeset() -> (ChangeSet, Enrichment) {
    let mut cs = ChangeSet::default();

    for i in 0..50 {
        cs.added.push(comp(&format!("added-{i}"), "1.0.0"));
    }
    for i in 0..20 {
        cs.removed.push(comp(&format!("removed-{i}"), "1.0.0"));
    }
    for i in 0..30 {
        let before = comp(&format!("ver-{i}"), "1.0.0");
        let after = comp(&format!("ver-{i}"), "2.0.0");
        cs.version_changed.push((before, after));
    }
    for i in 0..5 {
        let mut before = comp(&format!("lic-{i}"), "1.0.0");
        before.licenses = vec!["MIT".to_string()];
        let mut after = comp(&format!("lic-{i}"), "1.0.0");
        after.licenses = vec!["GPL-3.0".to_string()];
        cs.license_changed.push((before, after));
    }

    let mut e = Enrichment::default();
    let mut vulns: HashMap<String, Vec<VulnRef>> = HashMap::new();
    for i in 0..15 {
        vulns.insert(
            format!("pkg:npm/added-{i}@1.0.0"),
            vec![VulnRef {
                id: format!("GHSA-test-{i:04}"),
                severity: Severity::High,
                aliases: Vec::new(),
            }],
        );
    }
    e.vulns = vulns;

    for i in 0..10 {
        e.typosquats.push(TyposquatFinding {
            component: comp(&format!("plain-crypto-{i}"), "1.0.0"),
            closest: format!("crypto-{i}"),
            score: 0.95,
        });
    }

    (cs, e)
}

fn bench_render(c: &mut Criterion) {
    let (cs, e) = synth_changeset();
    let mut g = c.benchmark_group("render");

    g.bench_function("markdown", |b| {
        b.iter(|| {
            let s = markdown::render(black_box(&cs), black_box(&e));
            black_box(s);
        });
    });

    g.bench_function("json", |b| {
        b.iter(|| {
            let s = json::render(black_box(&cs), black_box(&e));
            black_box(s);
        });
    });

    g.bench_function("sarif", |b| {
        b.iter(|| {
            let s = sarif::render(black_box(&cs), black_box(&e));
            black_box(s);
        });
    });

    g.bench_function("terminal", |b| {
        b.iter(|| {
            let s = term::render(black_box(&cs), black_box(&e));
            black_box(s);
        });
    });

    g.finish();
}

criterion_group!(benches, bench_render);
criterion_main!(benches);
