# Contributing

Thanks for considering a contribution! bomdrift is intentionally small
and the contribution loop is fast.

## Development loop

```bash
git clone https://github.com/Metbcy/bomdrift
cd bomdrift

cargo check --all-targets       # fast feedback while editing
cargo test --release            # full test suite (~217 tests as of v0.3)
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --all --check         # MUST pass; run `cargo fmt --all` to fix
```

Rust 1.85+ required (the project uses edition 2024).

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
