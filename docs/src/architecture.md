# Architecture

bomdrift is a single-binary Rust CLI with three logical layers: **parse**,
**diff**, **enrich + render**. Every layer is pure (no shared mutable
state) so the same input produces byte-identical output every time —
the upsert contract.

## Module layout

```text
src/
├── main.rs            — clap entry point; dispatches to lib::run
├── lib.rs             — top-level wiring: load_sbom -> diff -> enrich -> render
├── cli.rs             — clap derive types: DiffArgs, RefreshArgs, FailOn, etc.
├── config.rs          — `.bomdrift.toml` policy (de)serialization + merge
├── clock.rs           — single source of truth for "now" (honors SOURCE_DATE_EPOCH)
├── attestation.rs     — `cosign verify-attestation` shell-out (v0.9.6)
├── plugin.rs          — external-process plugin loader (v0.9.6)
├── vex.rs             — VEX consume (OpenVEX 0.2.0, CycloneDX VEX 1.6) + emit (OpenVEX)
├── baseline.rs        — `--baseline` snapshot suppression + `expires`/`reason`/`vex_status`
├── refresh.rs         — `bomdrift refresh-typosquat` subcommand
├── model/             — unified component / SBOM types
│   ├── component.rs   — Component, Ecosystem, Hash, Relationship
│   └── sbom.rs        — Sbom, SbomFormat
├── parse/             — format-specific parsers
│   ├── cyclonedx.rs   — CDX 1.5/1.6 JSON
│   ├── spdx.rs        — SPDX 2.3 JSON
│   └── syft.rs        — Syft JSON
├── diff/              — pair-by-version ChangeSet computation
│   ├── mod.rs         — diff(), ChangeSet
│   └── key.rs         — ComponentKey (purl-without-version | (eco, name))
├── enrich/            — risk-signal enrichers
│   ├── osv.rs         — OSV.dev /v1/querybatch + /v1/vulns/{id}
│   ├── epss.rs        — FIRST.org EPSS per-CVE scores (v0.8)
│   ├── kev.rs         — CISA KEV catalog (v0.8)
│   ├── registry.rs    — npm / PyPI / crates.io metadata (v0.9)
│   ├── license.rs     — SPDX expression evaluation + allow/deny + per-exception (v0.8 / v0.9 / v0.9.5)
│   ├── typosquat.rs   — Jaro-Winkler + suffix boost / Levenshtein / last-segment / package-portion
│   ├── version_jump.rs — major-delta >= 2 heuristic
│   ├── maintainer.rs  — GitHub REST contributor-age (the xz pattern)
│   ├── cache.rs       — single source of truth for CACHE_TTL_SECS (v0.9.6 unified)
│   └── mod.rs         — Enrichment graph aggregating findings
└── render/            — output formatters
    ├── markdown.rs    — GFM PR-comment body
    ├── term.rs        — TTY-aware ANSI
    ├── json.rs        — pretty-printed serde graph
    └── sarif.rs       — SARIF v2.1.0 with stable rule IDs + partialFingerprints
```

## The pipeline

```text
                          OSV.dev /querybatch + /vulns/{id}
                                      |
                                      v
SBOM file --[parse::*]--> Sbom --+   /Enrichment\
                                 |  | - vulns    | -- typosquat (pure)
SBOM file --[parse::*]--> Sbom --+--+ - typosq's | -- version_jump (pure)
                                 |  | - jumps    | -- maintainer (GitHub API)
                                 v  | - main_age |
                              ChangeSet  --------/
                                 |
                                 v
                            (--baseline applies here, suppresses findings)
                                 |
                                 v
                              render::*
                                 |
                                 v
                       markdown / term / json / sarif
```

### `parse` layer

Each parser is hand-rolled (~150 LOC). We deliberately avoid the
`cyclonedx-bom` and `spdx-rs` crates: their dep trees are heavy
relative to the parsing surface we actually use, and the SBOM JSON
shapes are stable enough that hand-rolling is low maintenance.

The unified [`model::Component`](https://docs.rs/bomdrift/latest/bomdrift/model/struct.Component.html)
carries:
- `name`, `version`, `ecosystem` (parsed from purl when available, fallback to the source SBOM's hint)
- `purl` (`Option<String>`), `bom_ref` (`Option<String>`)
- `licenses: Vec<String>` (canonicalized to SPDX expressions when possible)
- `hashes: Vec<Hash>`, `supplier: Option<String>`, `source_url: Option<String>`, `relationship`

`SbomFormat::auto_detect` looks at top-level JSON fields to dispatch:
`bomFormat: "CycloneDX"` → CDX, `spdxVersion: "..."` → SPDX, `schema:
{name: "Syft"}` → Syft. `--format <FORMAT>` overrides detection.

### `diff` layer

The diff core groups components by `ComponentKey` and computes per-key:

```text
B = group_by_key(before.components)
A = group_by_key(after.components)

for K in keys(B) ∪ keys(A):
    versions in A[K] \ B[K] → ChangeSet::added
    versions in B[K] \ A[K] → ChangeSet::removed
    versions in A[K] ∩ B[K] with differing licenses → ChangeSet::license_changed
    legacy single-version case (|B[K]| = |A[K]| = 1, versions differ)
        → ChangeSet::version_changed (folds in license-changes-with-version-bumps)
```

`ComponentKey` is `Purl(string-without-version)` when the component
has a parseable purl, else `NameTuple(Ecosystem, name)`. This is what
makes cross-format diffs work: a CDX SBOM diffed against an SPDX SBOM
of the same project keys consistently across the two formats.

The `BTreeMap`-based grouping is what gives the diff its byte-deterministic
ordering. No timestamps leak in, no insertion-order leakage. The
`is_deterministic` integration test guards the contract.

### `enrich` layer

Enrichers are independent. Each takes a `&ChangeSet`, returns its
specific finding type (`Vec<TyposquatFinding>`,
`Vec<VersionJumpFinding>`, etc.), and the lib's `run_diff` aggregates
them into a single `Enrichment` graph.

Best-effort contract:
1. Per-request timeout (15s).
2. Errors warn once, never block.
3. Per-component caching within a single run.

The OSV enricher is the only one that touches a persistent on-disk
cache (`<XDG_CACHE_HOME>/bomdrift/osv/`). All other enrichers are
either pure-compute or only cache within a single process.

### `render` layer

Renderers are pure functions: `(ChangeSet, Enrichment) → String`. The
markdown renderer is the canonical "PR comment" path; terminal is the
TTY default; JSON is the downstream-tooling shape; SARIF is for Code
Scanning ingestion.

Determinism is the upsert contract:

- `Enrichment::vulns` is a `HashMap` (the OSV enricher fills it via
  unordered batch responses). Renderers that emit it (markdown, JSON,
  SARIF) sort the keys before emission.
- `Enrichment::typosquats` / `version_jumps` / `maintainer_age` are
  `Vec`s populated in `cs.added` / `cs.version_changed` iteration
  order — which is BTreeMap-derived, so stable.
- `ChangeSet::added` / `removed` / `version_changed` /
  `license_changed` are `Vec`s populated in `BTreeMap<ComponentKey, ...>`
  iteration order.

Result: identical inputs render to byte-identical output every time,
which is what `peter-evans/create-or-update-comment` relies on for the
upsert behavior in the action.

## Best-effort enricher contract

Every enricher — network (OSV / EPSS / KEV / GitHub / registries),
shell-out (cosign attestation), or external process (plugins) — honors
the same fail-soft contract:

1. **Per-request timeout** so a misbehaving upstream can't hang a CI job.
2. **Errors warn once to stderr** (deduped by key) and the diff renders
   without that source's findings.
3. **Per-component caching within a single run** so monorepo subpackages
   sharing a parent project don't multiply HTTP requests.
4. **Best-effort never blocks the diff render.** Exit code stays 0 from
   the enricher itself; the only way an enricher influences exit code is
   indirectly via `--fail-on` thresholds tripping on findings it
   produced.

`src/enrich/osv.rs` is the canonical pattern; new enrichers MUST mirror
its `Result<Vec<Finding>>`-where-`Err`-is-warned-not-propagated shape.
The `attestation.rs` and `plugin.rs` modules apply the same contract to
non-network shell-outs: a missing `cosign` binary, a plugin timeout, or
a malformed plugin response all warn and continue.

## Byte-determinism contract

Identical inputs MUST render to byte-identical outputs across every
format. This is what `peter-evans/create-or-update-comment` relies on
to upsert a PR comment in place rather than accumulating duplicates,
and what makes SARIF / VEX / JSON safe to commit to git.

Concretely:

- All `HashMap`s emitted into output are sorted by key first.
- All `Vec`s populated from `cs.added` / `version_changed` iteration
  inherit the diff core's BTreeMap-derived order.
- Every "now" reference goes through `clock::now()`, which honors
  `SOURCE_DATE_EPOCH` for reproducible-build contexts and for tests.
- VEX `@id` UUIDs and CycloneDX VEX `bom-ref` strings are deterministic
  hashes of the finding tuple, never random.

Tests that mutate `SOURCE_DATE_EPOCH` MUST acquire `clock::test_env_lock()`
to serialize across the crate's parallel test threads — a v0.9.5
discovery during the `release/v0.9.5` cleanup. See
[Contributing](./contributing.md#test-conventions-v095) for the recipe.

## Why no async / tokio?

bomdrift is intentionally **synchronous**. The single-binary CLI runs
to completion in seconds; concurrent network requests would shave
maybe 1–2 seconds off the OSV enricher path on diffs with > 100
unique CVEs, at the cost of:

- ~70 transitive crates (tokio, mio, futures, ...).
- A panic-on-blocking-call class of bug that's a constant
  trap for contributors.
- A bigger, slower-to-build, slower-to-link binary.

The OSV `/v1/querybatch` endpoint already batches (1000 queries per
request), so the parallelism we'd want is mostly already there. The
N+1 stage-2 `/v1/vulns/{id}` calls are gated by the on-disk severity
cache, which makes reruns within the configured TTL essentially free.

Plugin processes (v0.9.6+) are also invoked synchronously: at most
one external child at a time, with a per-component timeout. Parallel
plugin execution would re-introduce the tokio dependency cost without
solving a measured bottleneck.

## Why no chrono / no semver / no octocrab?

Same reasoning. We need:

- **One** ISO-8601 timestamp shape (the canonical `YYYY-MM-DDTHH:MM:SSZ`
  GitHub always emits). Hand-rolled parser is ~25 LOC, lives in
  `clock.rs`.
- **The major version** of a SemVer string. Hand-rolled extractor is
  ~5 LOC in `enrich/version_jump.rs`.
- **GitHub REST**: a small set of endpoints (contributors, commits)
  hand-rolled atop `ureq`. `octocrab` would pull in tokio.

All three pulls would add transitive weight for no functional gain.
The constraint is documented at the top of each affected file so future
contributors don't reflexively reach for the popular crate.

## Approved dependencies

As of v0.9.6:

| Crate | Purpose | Notes |
|---|---|---|
| `clap` | CLI parsing | derive feature only |
| `serde`, `serde_json` | (de)serialization | parse + render |
| `anyhow`, `thiserror` | error types | |
| `ureq` | HTTP | sync, rustls — no tokio |
| `strsim` | typosquat scoring | Jaro-Winkler + Levenshtein |
| `owo-colors`, `supports-color` | terminal renderer | |
| `directories` | XDG paths | |
| `toml` | `.bomdrift.toml` parsing | |
| `time = "0.3.47"` | timestamp formatting | minimal feature set |
| `sha2 = "0.10"` | partialFingerprint hashes (SARIF), VEX `@id` | |
| `spdx = "=0.10.9"` | exact-pinned SPDX expression evaluation | License-policy semantics shift on minor list updates; pin exactly |
| `base64 = "0.22"` | OCI attestation payload decoding (v0.9.6) | |
| `wait-timeout = "0.2"` | bounded plugin-process wait on Windows (v0.9.7) | sidesteps `Command::kill()`'s Windows quirks; tiny dep, no transitive weight |

Forbidden by policy: `tokio`, `chrono`, `semver`, `octocrab`,
`async-trait`, anything pulling rustls + ring + tokio transitively
beyond what `ureq` already brings.

## Binary size budget

- **Target**: ≤ 5 MB stripped + LTO on Linux x86_64.
- **Current** (v0.9.6): ~3.4 MB.
- **Audit**: `cargo bloat --release --crates -n 20` periodically to
  confirm no unexpected dep-tree growth.

## Module size budget

- **Soft cap**: ≤ 1000 LOC per file in `src/` (incl. `#[cfg(test)] mod tests`).
  At ~1000 LOC the file usually contains more than one cohesive concern
  and review attention starts skipping the middle.
- **Hard cap**: ≤ 1500 LOC. Past this, split before adding new behavior;
  PR #44 (markdown.rs → markdown/{mod,components,vulns,...}.rs) is the
  reference shape for how the split should look.
- **Audit**: `find src -name '*.rs' -exec wc -l {} \; | sort -rn | head`
  during release prep. Any file past the soft cap goes into the next
  refactor cycle's candidate list; any file past the hard cap blocks
  the release until split or explicitly waived in the changelog.
- Tests-only files (`tests/**`) are exempt — large integration tests
  are easier to read as one file than as a maze of helpers.

## Perf reference: diff core benchmark

The diff core (`src/diff/`) runs on every bomdrift invocation, so it
has its own criterion bench under [`benches/diff.rs`][diff-bench].
That bench is the perf reference for any change that touches diff
internals (`group_by_key`, `diff_one_key`, the multi-version
pair-by-version logic).

Three workloads per size (500, 5_000, opt-in 20_000 with
`--features bench-stress`):

- **end_to_end** — realistic mix (80% unchanged, 10% version_changed,
  5% license_changed, 5% added/removed). Production hot path.
- **self_diff** — identical inputs. Lower bound on diff cost; isolates
  `group_by_key` BTreeMap construction + per-key iteration with no
  change-pair work.
- **all_license_changed** — every intersecting pair has a different
  license set. Isolates the license-comparison branch.

Run with `cargo bench --bench diff` (under 30s on a laptop). Record
medians in the PR description for any change that touches
`src/diff/`; a >5% regression on the production `end_to_end / 5000`
workload warrants either a fix or an explicit explanation.

[diff-bench]: https://github.com/Metbcy/bomdrift/blob/main/benches/diff.rs
