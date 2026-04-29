# Architecture

bomdrift is a single-binary Rust CLI with three logical layers: **parse**,
**diff**, **enrich + render**. Every layer is pure (no shared mutable
state) so the same input produces byte-identical output every time —
the upsert contract.

## Module layout

```text
src/
├── main.rs           — clap entry point; dispatches to lib::run
├── lib.rs            — top-level wiring: load_sbom -> diff -> enrich -> render
├── cli.rs            — clap derive types: DiffArgs, RefreshArgs, FailOn, etc.
├── model/            — unified component / SBOM types
│   ├── component.rs  — Component, Ecosystem, Hash, Relationship
│   └── sbom.rs       — Sbom, SbomFormat
├── parse/            — format-specific parsers
│   ├── cyclonedx.rs  — CDX 1.5/1.6 JSON
│   ├── spdx.rs       — SPDX 2.3 JSON
│   └── syft.rs       — Syft JSON
├── diff/             — pair-by-version ChangeSet computation
│   ├── mod.rs        — diff(), ChangeSet
│   └── key.rs        — ComponentKey (purl-without-version | (eco, name))
├── enrich/           — risk-signal enrichers
│   ├── osv.rs        — OSV.dev /v1/querybatch + /v1/vulns/{id}
│   ├── cache.rs      — on-disk OSV severity cache (24h TTL)
│   ├── typosquat.rs  — Jaro-Winkler + suffix boost (npm/PyPI/Cargo); Levenshtein (Maven)
│   ├── version_jump.rs — major-delta >= 2 heuristic
│   ├── maintainer.rs — GitHub REST contributor age
│   └── mod.rs        — Enrichment graph aggregating findings
├── baseline.rs       — load + apply --baseline JSON snapshots
├── refresh.rs        — bomdrift refresh-typosquat subcommand
└── render/           — output formatters
    ├── markdown.rs   — GFM PR-comment body
    ├── term.rs       — TTY-aware ANSI
    ├── json.rs       — pretty-printed serde graph
    └── sarif.rs      — SARIF v2.1.0 with stable rule IDs
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
cache, which makes reruns within 24h essentially free.

## Why no chrono / no semver?

Same reasoning. We need:
- **One** ISO-8601 timestamp shape (the canonical `YYYY-MM-DDTHH:MM:SSZ`
  GitHub always emits). Hand-rolled parser is ~25 LOC.
- **The major version** of a SemVer string. Hand-rolled extractor is ~5 LOC.

Both pulls would add transitive weight for no functional gain. The
constraint is documented at the top of each file (`enrich/maintainer.rs`,
`enrich/version_jump.rs`) so future contributors don't reflexively
reach for the popular crate.

## Binary size budget

- **Target**: ≤ 5 MB stripped + LTO on Linux x86_64.
- **Current** (v0.3.0): ~3.4 MB.
- **Audit**: `cargo bloat --release --crates -n 20` periodically
  to confirm no unexpected dep-tree growth.

The dep tree as of v0.3:

```text
clap (CLI)
serde + serde_json (parse/render)
anyhow + thiserror (errors)
ureq + rustls + ring (HTTP)
strsim (typosquat)
owo-colors + supports-color (terminal)
directories (XDG paths)
```

No tokio, no chrono, no octocrab, no semver, no async-trait. The
constraint is load-bearing: keep the binary small enough that cosign
verification + extraction stay sub-second on cold runners.
