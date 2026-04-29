# bomdrift examples

Self-contained scenarios showing each of bomdrift's risk signals firing on
synthetic SBOM pairs. Every example is runnable with the offline-mode flags
(`--no-osv --no-maintainer-age`) so a `cargo build` is the only prerequisite.

| Scenario                                         | What it demonstrates                                                                  |
|--------------------------------------------------|---------------------------------------------------------------------------------------|
| [`axios-incident/`](./axios-incident/)           | The headline scenario: a typosquat (`plain-crypto-js`) added alongside a version bump on a compromised release. Three signals (added / version-changed / typosquat) fire in one diff. |
| [`multi-ecosystem/`](./multi-ecosystem/)         | Per-ecosystem typosquat detection across **npm**, **PyPI**, **Cargo**, and **Maven** — four findings in a single offline pass.                                                       |
| [`version-jumps/`](./version-jumps/)             | Multi-major version-jump heuristic catching `1.x → 4.x`, `2.x → 4.x`, `3.x → 5.x` upgrades in one diff.                                                                              |
| [`baseline-suppression/`](./baseline-suppression/) | `--baseline <path.json>` suppresses a finding that's already been triaged, so adopting bomdrift on an existing project doesn't drown the first PR comment.                          |

## Running an example

Each subdirectory has a `README.md` describing the scenario and a `before.json`
+ `after.json` SBOM pair. From the repo root:

```bash
cargo build --release
./target/release/bomdrift diff \
  examples/axios-incident/before.json \
  examples/axios-incident/after.json \
  --no-osv --no-maintainer-age
```

## Running them all at once

[`run-all.sh`](./run-all.sh) walks every scenario, regenerates the rendered
output, and diffs it against the pinned `expected-output.md`. Used by the
docs-polish workflow as a smoke test that the examples haven't drifted from
the binary's behavior.

```bash
bash examples/run-all.sh
```

The script exits 0 when every scenario's rendered output matches its pinned
expectation, non-zero otherwise.

## Why offline mode?

The examples are pinned to the *deterministic* signals — change shape,
typosquat, version-jump. The OSV.dev CVE enricher and the GitHub-API
maintainer-age signal both touch live network state that drifts week-to-week
(new advisories get published, contributor stats shift). Running these
examples with full network access still works and the change shape stays
identical, but the **Vulnerabilities** and **Young maintainers** sections
will show different content from what the pinned `expected-output.md`
captures.

If you want to see the live signals in action against these fixtures, drop
the `--no-osv --no-maintainer-age` flags:

```bash
bomdrift diff examples/axios-incident/before.json examples/axios-incident/after.json
```

## Adding a new example

1. Create `examples/<scenario>/` with `before.json`, `after.json`, and a
   `README.md` describing what signal(s) fire.
2. Generate the pinned reference output:
   ```bash
   ./target/release/bomdrift diff \
     examples/<scenario>/before.json \
     examples/<scenario>/after.json \
     --no-osv --no-maintainer-age \
     --output markdown > examples/<scenario>/expected-output.md
   ```
3. Add an entry to the table at the top of this README.
4. `bash examples/run-all.sh` should pass.
