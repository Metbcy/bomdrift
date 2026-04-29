## What this PR does

<!-- One or two sentences. Why this change exists is more interesting
than what the diff does — `git diff` shows the what. -->

## Test coverage

<!-- Pick one. -->

- [ ] New unit test(s) in `src/<module>/tests`
- [ ] New integration test in `tests/integration.rs`
- [ ] New CLI end-to-end test in `tests/cli.rs`
- [ ] New real-world regression in `tests/real_world.rs` + fixture in `tests/fixtures/real-world/`
- [ ] No new tests (explain why below)

## Verification gates

- [ ] `cargo fmt --all --check` clean
- [ ] `cargo clippy --all-targets --all-features -- -D warnings` clean
- [ ] `cargo test --release` clean
- [ ] `bash examples/run-all.sh` clean (if behavior or rendered-output changes touched the example fixtures)
- [ ] `mdbook build docs` clean (if any `docs/src/**.md` changed)

## Linked issues

<!-- "Closes #123" or "Refs #456" -->

## Anything reviewers should know

<!-- Tradeoffs, alternatives considered, follow-up work that's
intentionally out of scope. -->
