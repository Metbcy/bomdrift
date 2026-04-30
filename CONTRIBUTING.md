# Contributing

Thanks for considering a contribution! bomdrift is intentionally small
and the contribution loop is fast.

## Looking for somewhere to start?

Issues labeled [`good first issue`](https://github.com/Metbcy/bomdrift/issues?q=is%3Aopen+is%3Aissue+label%3A%22good+first+issue%22)
are scoped for first-time contributors:

- Add a name to one of the typosquat top-N lists
  (`data/<eco>-top*.txt` — see the comment header in any of those files).
- Fix a doc typo (mdBook in `docs/`, README, or any module-level
  `//!` comment).
- Improve an error message (bomdrift's `anyhow` chains can usually be
  more specific about what failed).
- Refresh a curated typosquat list from its upstream source (snapshot
  date is in the file header).

For larger changes (a new enricher, a new ecosystem, an output-format
addition), open a **discussion or issue first** so we can talk
through the design before you sink time into a PR.

## Development loop

```bash
git clone https://github.com/Metbcy/bomdrift
cd bomdrift

cargo check --all-targets       # fast feedback while editing
cargo test --release            # full test suite (~420 tests as of v0.9.6)
rustup run 1.88 cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --all -- --check      # MUST pass; run `cargo fmt --all` to fix
```

Rust 1.88+ required (the project uses edition 2024; CI is pinned to
1.88 to keep clippy lints stable across releases — see
`Cargo.toml`'s `rust-version` field).

## Project conventions

### Commits

[Conventional Commits](https://www.conventionalcommits.org/):

- `feat(scope): add X` — new feature
- `fix(scope): Y` — bug fix
- `docs(scope): Z` — documentation only
- `chore: W` — maintenance with no behavioral change

Commit bodies should explain *why*, not *what* — `git diff` shows the
*what*. Multi-line commit messages are fine; use the heredoc
`git commit -m "$(cat <<'EOF' ... EOF)"` pattern for readability.

### Commit signing on `main`

`main` enforces `required_signatures` via the repository ruleset.
**This does NOT mean PR contributors need GPG/SSH signing keys
configured.** Here's how it actually shakes out:

| You're a... | Do you need to sign? |
|---|---|
| Contributor opening a PR from a fork or feature branch | **No.** Push commits as-is. The maintainer chooses the merge method. |
| Maintainer merging via `gh pr merge --merge` | **No.** GitHub's web-UI key signs the merge commit; it counts as verified. |
| Maintainer merging via `gh pr merge --squash` | **No.** Same — GitHub signs the squash commit. |
| Maintainer merging via `gh pr merge --rebase` | **Yes.** Rebase replays your PR commits verbatim onto `main`, so they must already be signed. |
| Anyone pushing directly to `main` | **Yes** (and the ruleset blocks it via `pull_request` anyway, so this only matters for emergency bypass). |

Practical rule of thumb for contributors: **don't worry about it**.
The maintainer will pick the right merge method.

If you'd like your commits to land verbatim on `main` for git-blame
attribution (and want to use rebase-merge), set up local signing once:

```bash
# SSH-key signing (simplest, no GPG headache)
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/id_ed25519.pub
git config --global commit.gpgsign true
```

Then add the same SSH public key to your GitHub account under
[SSH and GPG keys → Signing keys](https://github.com/settings/keys).

### Branch model

Single-purpose feature branches off `main`, merged via merge-commits
(`git merge --no-ff`) so the fan-out graph stays readable. Push the
feature branch alongside the merge to preserve the history visually
on the GitHub network graph.

### No emojis in code or rendered output

Strictly bracketed-prefix everything (`[ADD]`, `[CVE]`, `[SQT]`, etc.).
This is for terminal accessibility, grepability of CI logs, and to
keep the markdown PR comment readable in monospace fonts.

### No `Co-authored-by: <yourself>` lines

The `Co-authored-by` trailer is reserved for collaborators who
genuinely co-authored the commit. The project's CI tooling adds its
own trailer; don't duplicate.

## Where to put new code

| If you're adding... | Put it in... |
|---|---|
| A new SBOM format parser | `src/parse/<format>.rs` + `parse::SbomFormat::auto_detect` |
| A new enricher | `src/enrich/<name>.rs` + add to `Enrichment` struct |
| A new output format | `src/render/<format>.rs` + `OutputFormat` clap enum |
| A new diff-core algorithm | `src/diff/` (rare; please open an issue first) |
| A new typosquat ecosystem | `data/<eco>-topN.txt` + `SupportedEcosystem` enum |
| A new CLI flag | `src/cli.rs` + wire through `lib.rs::run_diff` |
| Documentation | `docs/src/<chapter>.md` + add to `docs/src/SUMMARY.md` |

## Tests

Three layers, all run by `cargo test --release`:

- **Unit tests** (`#[cfg(test)] mod tests` inside each `src/<module>.rs`):
  test the smallest unit. Mock at the function-argument boundary
  (e.g. inject a fake `fn fetcher(url) -> Result<Vec<u8>>` for network
  enrichers).
- **CLI tests** (`tests/cli.rs`): spawn the actual `bomdrift` binary
  via `CARGO_BIN_EXE_bomdrift` and assert on stdout/stderr/exit code.
  These are end-to-end and slower; reserve them for user-visible
  surface (flags, output shape).
- **Integration tests** (`tests/integration.rs`): exercise the
  library API directly without spawning the binary. Faster than CLI
  tests but cheaper than spinning up the full process.

Network-touching enrichers should have a unit test for the network-
failure path (fake fetcher returns `Err`) — the best-effort contract
matters and silently breaking it would be an easy regression.

### Coverage (v0.9.8+)

CI runs `cargo llvm-cov` on every PR and posts a sticky comment with
the overall line coverage % (the full `lcov.info` is uploaded as a
workflow artifact). The job is informational for now — there is no
`--fail-under-lines` threshold yet. The plan is to add a ratchet in
v0.9.9 once 2–3 releases have made the baseline visible. Until then,
the report is a nudge, not a gate; PRs that move coverage in the
wrong direction without justification will get a review comment, not
a red check.

### Test conventions (v0.9.5+)

Tests that mutate `SOURCE_DATE_EPOCH` (directly or indirectly via
`bomdrift::clock::*`) MUST acquire `clock::test_env_lock()` to serialize
across the crate's parallel test threads. Without the lock, two tests
running in parallel can read each other's mutated env var and
intermittently fail in ways that look format-deterministic but aren't.

```rust
#[test]
fn baseline_expiry_relative_to_source_date_epoch() {
    let _lock = bomdrift::clock::test_env_lock();
    // SAFETY: serialized by _lock above.
    unsafe { std::env::set_var("SOURCE_DATE_EPOCH", "1735689600") }; // 2025-01-01
    // ... test body ...
}
```

The lock is a `std::sync::Mutex<()>` — re-entrant calls within a single
test thread are fine, but a panic without the guard will poison it. If
you see "PoisonError" in CI but not locally, a previous test panicked
without releasing — fix the panicking test, not the poison handling.

### Adding a new enricher

The shortest viable PR shape, mirroring how `enrich::epss` was added in
v0.8 and `enrich::registry` in v0.9:

1. **`src/enrich/<name>.rs`** — pure `enrich(cs: &ChangeSet, ...) ->
   Vec<<Name>Finding>` with a fail-soft fetcher boundary. Mirror the
   shape of `src/enrich/osv.rs`.
2. **Wire into `Enrichment`** — add a field to the
   `bomdrift::enrich::Enrichment` struct in `src/enrich/mod.rs`; have
   `lib.rs::run_diff` populate it.
3. **Add a `--no-<name>` flag** to `src/cli.rs::DiffArgs`, plumb
   through the `[diff] no_<name>` config key.
4. **Renderers** — add a section to `render::markdown`,
   `render::term`, `render::json`. For SARIF, add a stable rule ID
   (`bomdrift.<name>`), a `partialFingerprints.primaryHash/v1`
   identity tuple, and a fingerprint-stability test.
5. **`--debug-calibration` row** — emit one
   `<kind>|<key>|<score>|<threshold>` line per finding considered.
6. **Docs** — add `docs/src/enrichers/<name>.md` and link it from
   `docs/src/SUMMARY.md` and `docs/src/enrichers/overview.md`.
7. **CHANGELOG** — `## [Unreleased]` entry under `### Added`.

### Adding a new finding kind

When a new finding kind is purely a rendering layer (e.g., a new
synthetic ID for VEX export or a new SARIF rule for an existing
enricher), the recipe is shorter:

1. **Synthetic-id grammar** — extend
   `bomdrift::vex::SyntheticFindingKind` and the
   `parse_synthetic_id` parser. Round-trip must be exact.
2. **SARIF rule** — add the rule descriptor to
   `render::sarif::ALL_RULES` so it appears in `tool.driver.rules`
   even with zero results, then a `partialFingerprints` identity
   tuple for the new rule.
3. **Markdown / terminal / JSON sections** — mirror the existing
   per-finding sections.
4. **Determinism test** — round-trip the rendered SARIF / VEX through
   the parser and assert byte-for-byte equality with the input.

## Documentation

When you add a CLI flag / action input / enricher, update:

1. The relevant chapter in `docs/src/`.
2. The CHANGELOG entry under `## [Unreleased]`.
3. The README's Features list (only for user-visible surface).
4. Module doc comment explaining *why* (`//! ...` at the top of the file).

mdBook builds with `cd docs && mdbook build`. The output renders to
`docs/book/`; check that locally before pushing.

## Reporting issues

For false positives / negatives in the heuristic enrichers (typosquat,
version-jump, maintainer-age), the most useful issue includes:

1. The component name + version that fired (or should have).
2. The expected behavior + observed behavior.
3. A minimal SBOM pair if possible (synthetic CDX 1.5 JSON works).

Open an issue at <https://github.com/Metbcy/bomdrift/issues>.

## Security disclosures

For supply-chain bugs in bomdrift itself — particularly anything that
could let bomdrift run untrusted input as code — please report
privately via [GitHub Security Advisories](https://github.com/Metbcy/bomdrift/security/advisories/new)
rather than a public issue.
