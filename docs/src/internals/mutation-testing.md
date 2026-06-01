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
