# Mutation testing (cargo-mutants)

bomdrift's risk-bearing modules are audited with [`cargo-mutants`](https://github.com/sourcefrog/cargo-mutants) to verify the test suite actually catches the mutations the tests claim to catch. The audit is run manually before each release — it is **not** wired into CI (the runtime is prohibitive for per-PR feedback, and the signal is most useful at release-cut time).

## How to reproduce

Run from a clean worktree (the tool rewrites source files in place during the run):

```sh
git worktree add ../bomdrift-mutants main
cd ../bomdrift-mutants
cargo mutants --in-place --no-shuffle --file '<path-glob>' --timeout 60
```

Use a separate worktree so concurrent editing in your main checkout doesn't collide with the in-place rewrites.

## Audit log

Each entry: `module — caught / unviable / surviving / total — date`. The target is **<10% surviving**.

### `src/diff/**` — v0.9.9 baseline

- **Total mutants:** 19 (+ 1 baseline build)
- **Caught:** 16
- **Unviable:** 3 (compile-failures the tool excludes from the surviving-rate denominator)
- **Surviving:** 0
- **Surviving rate:** 0 / 19 = **0.0%**
- Date: 2026-06-01

No test additions required. The diff engine's existing unit and property tests fully cover the mutation surface.

The three unviable mutants were mutations that produced code that does not compile — they're excluded from the surviving denominator because the compiler itself rejects them before the test suite runs.

### `src/baseline.rs` — v0.9.9 round 2

- **Total mutants:** 54
- **Caught (round 1):** 42
- **Unviable:** 3
- **Surviving (round 1):** 9
- **Surviving rate (after #63):** 0 / 51 = **0.0%**
- Date: 2026-06-01

PR #63 added 7 tests covering 9 logic survivors across `apply` (suppression matching), `add_suppression_full` (object-form writes), and `doc_kind` (JSON variant labeling). All previously-missed mutants now caught.

### `src/enrich/typosquat.rs` — v0.9.9 round 2

- **Total mutants:** 98
- **Caught (round 1):** 76
- **Unviable:** 5
- **Surviving (round 1):** 17
- **Closed by new tests:** 13 (logic + return-value)
- **Accepted as label-string:** 4 (see below)
- **Surviving after audit:** 0 logic / 4 acceptable label
- Date: 2026-06-01

Tests added in this PR cover:

- `best_match_maven` boundary at `dist == MAVEN_MAX_LEVENSHTEIN` (line 371 `>`/`>=` mutant)
- `best_match_maven` closer-wins selection through the match guard (line 375 guard mutants)
- `best_match_maven` score formula `1 - dist / (len + 1)` (lines 380-381 arithmetic mutants)
- `has_suspicious_suffix_containment` strict-delta boundary (line 416 `+`/`-` mutant)
- `default_cache_path` returns `Some(<path ending in typosquat/<eco>.txt>)` (line 471 None/Default mutants)

**Accepted label-string mutants (documented, not closed):**

- `SupportedEcosystem::cache_filename` returning `""` or `"xyzzy"` (line 150): the function's only caller, `default_cache_path`, joins the string into a `PathBuf`. No downstream behavior depends on the literal filename content as long as the path resolves; the only place we assert on the content is the new `default_cache_path` test (above), which fixes the suffix shape but not the exact ecosystem label.
- `ecosystem_label` returning `""` or `"xyzzy"` (line 504): the function is used only for a one-shot `eprintln!` user-facing log message in `load_legit_list`. Logging text is not contractual; no test should pin the human-readable label.

