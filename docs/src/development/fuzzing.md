# Property-based testing

bomdrift uses [proptest](https://altsysrq.github.io/proptest-book/) for
property-based tests of the parser, diff core, typosquat canonicalization,
and version-jump extractor. Property tests run as part of `cargo test`
alongside the unit tests — there's no separate harness.

## What's tested

### Parser layer

> **Hypothesis**: feeding arbitrary bytes through
> `serde_json::from_slice` followed by `parse_with_format` must NEVER
> panic. Errors are fine; panics are bugs.

Tests in `src/parse/mod.rs::tests`:

- **`parse_pipeline_does_not_panic_on_arbitrary_bytes`** — 1024 random
  byte sequences (0–2048 bytes each). Most error at JSON parse; the
  few valid-JSON-but-not-an-SBOM cases exercise the parser's error
  paths.
- **`parse_pipeline_does_not_panic_on_arbitrary_json`** — 1024 random
  serde_json::Value trees up to depth 3. Far more efficient at
  exploring the parser's behavior on well-formed-JSON-but-not-an-SBOM
  than random bytes.
- **`parse_pipeline_does_not_panic_with_format_hint`** — same as above
  but with each `SbomFormat` hint forced. Catches per-parser panics
  that auto-detect would have routed away from.
- **`ecosystem_from_purl_does_not_panic`** — arbitrary unicode strings
  through the purl-type extractor.
- **`hash_alg_does_not_panic`** — arbitrary algorithm strings through
  the hash-algorithm normalizer.

### Typosquat canonicalization

Tests in `src/enrich/typosquat.rs::tests`:

- **`pep503_normalize_does_not_panic`** — arbitrary unicode through the
  PyPI normalizer. Output invariants asserted: lowercase only, no
  leading/trailing dashes.
- **`last_path_segment_returns_substring`** — arbitrary unicode through
  the Go/Composer match-form extractor. The result must be a substring
  of the input and must contain no `/`.
- **`enrich_does_not_panic_on_arbitrary_components`** — random
  ChangeSets with up to 32 added components of varying ecosystems must
  go through the full enrich() path without panicking.

### Diff core

Tests in `src/diff/mod.rs::tests`:

- **`diff_self_is_empty`** — for any `Sbom`, `diff(a, a)` produces an
  empty `ChangeSet`. The strongest invariant; catches parser non-
  determinism that other tests miss.
- **`diff_swap_roles_when_inputs_swapped`** — `diff(a, b)` and
  `diff(b, a)` swap `added`/`removed` cardinalities and preserve
  `version_changed` and `license_changed` cardinalities. Catches
  asymmetric bugs in the per-key dispatch.
- **`diff_is_deterministic`** — two calls on the same input produce
  byte-equal `ChangeSet` structures. The upsert contract for the
  PR-comment renderer relies on this.

### Version-jump extractor

Tests in `src/enrich/version_jump.rs::tests`:

- **`extract_major_does_not_panic`** — arbitrary strings through
  `extract_major()`.
- **`extract_major_round_trips_well_formed_numerics`** — for any
  major version 1..10000, the function round-trips the bare form,
  the `v`-prefixed form, and the pre-release suffix form.
- **`extract_major_handles_unicode_without_panic`** — arbitrary
  unicode prefix + a well-formed version number. The function should
  treat the prefix as garbage (return None) but never panic.

## Why property-based, not cargo-fuzz?

- **Stable Rust.** proptest works on the stable toolchain; cargo-fuzz
  requires nightly via the `libFuzzer` LLVM coverage instrumentation.
- **Runs as part of `cargo test`.** No separate harness, no
  cross-build complexity, no CI configuration delta. Every PR runs
  the property tests automatically.
- **Counterexample shrinking.** When a property fails, proptest
  shrinks the failing input toward a minimal reproduction. The
  resulting test failure is much easier to debug than a 2KB random
  byte sequence from libFuzzer's corpus.

The trade-off is corpus persistence — proptest doesn't accumulate a
crash corpus the way libFuzzer does. For a tool of bomdrift's size
that's a fair trade; if the project grows to need long-running fuzz
campaigns, a future contributor can wire up cargo-fuzz alongside
proptest.

## Running

```bash
# Run all tests including property tests
cargo test --release

# Just one property test
cargo test --release diff_self_is_empty

# Increase case count for thorough exploration
PROPTEST_CASES=10000 cargo test --release diff_self_is_empty
```

The default case counts (512–2048 per property) are calibrated so the
full test suite finishes in ~2 seconds. Bump `PROPTEST_CASES` for
deeper exploration on a release machine.

## When a property test fails

1. proptest prints a minimized counterexample. Copy it verbatim into a
   new unit test in the same module.
2. Add a `#[test]` that exercises the counterexample directly. This
   becomes a regression guard; the property test's randomness alone
   isn't sufficient long-term coverage for a known-bad input.
3. Fix the bug.
4. Both the property test and the new unit test should now pass.

## Real-world SBOM regression corpus

In addition to property tests, bomdrift ships a corpus of real-world
SBOMs in `tests/fixtures/real-world/` (sourced from the official
CycloneDX and SPDX example repos). The regression tests in
`tests/real_world.rs` exercise:

- Every fixture parses without error.
- Every fixture has at least one component.
- Components with known purl types (`pkg:npm/`, `pkg:pypi/`, etc.)
  resolve to the canonical `Ecosystem` variant — not to
  `Ecosystem::Other(_)`.
- Diffing two unrelated real-world SBOMs doesn't panic.
- Self-diffing a real-world SBOM produces an empty ChangeSet.
- All four renderers produce non-empty output on a real diff.

The corpus is kept small (~2.7 MB total) so test runtime stays
sub-second. Refresh it by re-fetching from upstream.
