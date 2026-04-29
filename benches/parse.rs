//! Benchmarks for the parser layer. Measures the time to:
//!
//! 1. `serde_json::from_slice` the SBOM body into a `Value` (the I/O-shape
//!    cost — most realistic when the SBOM has been read from disk already).
//! 2. `parse::parse_with_format` dispatch into the format-specific parser
//!    and produce a `model::Sbom` (the canonical-model cost).
//!
//! These two steps are reported separately so a regression in either layer
//! is attributable. Run with `cargo bench --bench parse`.

use std::fs;

use criterion::{Criterion, black_box, criterion_group, criterion_main};

use bomdrift::parse;

const FIXTURES: &[(&str, &str)] = &[
    ("cdx", "tests/fixtures/cdx-minimal.json"),
    ("spdx", "tests/fixtures/spdx-minimal.json"),
    ("syft", "tests/fixtures/syft-minimal.json"),
];

fn bench_parse(c: &mut Criterion) {
    for (label, path) in FIXTURES {
        let body = fs::read_to_string(path).expect("fixture must be readable");
        let mut g = c.benchmark_group(format!("parse/{label}"));

        // Stage 1: JSON deserialization only.
        g.bench_function("json_value", |b| {
            b.iter(|| {
                let v: serde_json::Value =
                    serde_json::from_str(black_box(&body)).expect("must parse JSON");
                black_box(v);
            });
        });

        // Stage 2: full pipeline (JSON value -> normalized Sbom).
        g.bench_function("full_pipeline", |b| {
            b.iter(|| {
                let v: serde_json::Value = serde_json::from_str(&body).expect("must parse JSON");
                let sbom =
                    parse::parse_with_format(black_box(v), None).expect("must normalize to Sbom");
                black_box(sbom);
            });
        });

        g.finish();
    }
}

criterion_group!(benches, bench_parse);
criterion_main!(benches);
