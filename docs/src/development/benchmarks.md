# Benchmarks

bomdrift uses [criterion](https://bheisler.github.io/criterion.rs/book/)
for benchmarking the four hot paths: parse, diff, typosquat, and render.
Benchmarks are not run in CI (the variance on shared GitHub runners is
±20%, which buries any real signal); they're a tool for validating
perf-relevant changes on hardware you control.

## Running

```bash
# Run all benchmarks
cargo bench

# Run just one harness
cargo bench --bench parse
cargo bench --bench diff
cargo bench --bench typosquat
cargo bench --bench render

# Filter inside a harness
cargo bench --bench typosquat -- npm_batch
```

Criterion writes an HTML report to `target/criterion/report/index.html`
on each run with throughput plots, distribution histograms, and
diff-against-previous-run charts.

## What each harness measures

### `parse` — SBOM parser layer

For each of the three fixture formats (CycloneDX, SPDX, Syft):

- **`json_value`**: cost of `serde_json::from_str` to a `Value` only.
  Captures the JSON-deserialization floor independent of bomdrift's
  parser.
- **`full_pipeline`**: cost of `from_str` + `parse_with_format` to a
  normalized `model::Sbom`. The delta vs `json_value` is bomdrift's
  parsing overhead.

A regression in the delta is the signal worth investigating — a
regression in `json_value` is a serde_json change.

### `diff` — diff core

- **`axios_fixture_pair`**: realistic small-PR shape (~3 components per
  side). The lower bound for any diff invocation.
- **`synth_monorepo_200`**: 200 components per side, half of them
  version-changed. The realistic monorepo upper bound for a single PR.
- **`synth_self_diff_200`**: same input on both sides. Worst case for
  the BTreeMap-intersection path with no resulting work to do.

A regression on `synth_monorepo_200` likely indicates a hot-loop
change in `diff_one_key`; a regression on `synth_self_diff_200` likely
indicates a `ComponentKey::Ord` change.

### `typosquat` — Jaro-Winkler scoring

- **`one_npm_typosquat_axios`**: a single candidate (`plain-crypto-js`)
  scored against the embedded npm top-1k list. The typosquat enricher's
  per-candidate cost.
- **`npm_batch` 10/50/100**: a batch of N candidates, exercising the
  per-candidate cost amortized.
- **`mixed_three_ecosystems`**: one candidate per ecosystem (npm + PyPI
  + Cargo), exercising the per-ecosystem dispatch and embedded-list
  load cost (after the OnceLock has been hit).

The first invocation of each ecosystem in a process pays the legit-list
parsing + canonicalization cost (~1ms for the npm 1k list); subsequent
invocations are hot. Criterion's `iter()` measures the cached path.

### `render` — output renderers

For each of markdown / JSON / SARIF / terminal, with a synthetic
ChangeSet shaped like a moderate PR (50 added / 20 removed / 30
version-changed / 5 license-changed + 10 typosquats + 15 CVEs).

A regression on one renderer specifically is usually a string-formatting
change in that file. A regression across all renderers is usually a
ChangeSet shape change that propagated.

## Suggested workflow for perf-relevant PRs

1. On a clean main, run `cargo bench` and let criterion record the
   baseline.
2. Switch to your branch, make the change, and run `cargo bench` again.
3. Criterion's HTML report shows a "Change vs previous" column with
   confidence intervals. ±5% is noise on most hardware; ±10%+ is worth
   looking at; statistical significance markers (criterion's "Performance
   has improved" / "Performance has regressed" lines) are the
   first-class signal.
4. If the change is intentional (e.g. a feature that adds a new pass),
   note the new baseline in the PR description so reviewers know to
   compare against the post-change number, not the pre-change one.

## Why no CI integration?

- Shared GitHub runners have ±20% variance run-over-run on these
  benchmarks. Real regressions are smaller than the noise floor.
- Self-hosted runners with pinned hardware would solve that, but the
  project doesn't have that infrastructure (and the operational cost
  isn't worth it at the project's scale).
- For now, run benchmarks locally on a quiet machine; a future
  contributor can wire up a self-hosted bench runner if the project
  grows enough to justify it.
