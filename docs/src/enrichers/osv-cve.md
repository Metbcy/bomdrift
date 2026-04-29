# OSV.dev CVE lookup

bomdrift's CVE enricher queries the [Open Source Vulnerability database](https://osv.dev/)
for added and version-bumped components, populating the **Vulnerabilities**
section in the rendered output with advisory IDs (CVE, GHSA, MAL, etc.)
and per-advisory severity.

## Two-stage lookup

### Stage 1: `/v1/querybatch`

A single batched POST returns advisory IDs for every queried component
in one round-trip. bomdrift batches up to 1000 queries per request (the
documented cap); larger diffs chunk into multiple batches.

Each query is a `package@version` keyed by purl ecosystem (`npm`, `PyPI`,
`crates.io`, `Maven`, etc.). Components without a parseable purl are
skipped silently.

### Stage 2: `/v1/vulns/{id}`

For each unique advisory ID returned by stage 1, bomdrift issues a
follow-up GET to populate severity. Severity is sourced (in order):

1. **GHSA's `database_specific.severity`** text label
   (`LOW|MODERATE|HIGH|CRITICAL`). This is the most consistent shape
   across the OSV corpus.
2. **Highest CVSS_V3 vector score** from the `severity[]` array, mapped
   to a label by the standard CVSS-v3 severity rating
   (Critical ≥ 9.0, High ≥ 7.0, Medium ≥ 4.0, Low ≥ 0.1).
3. **`Severity::None`** when neither shape is present. These advisories
   render with a `none` severity label and don't trip
   `--fail-on critical-cve`.

## On-disk severity cache

Stage-2 lookups are N+1 in the worst case — one query per unique
advisory ID. bomdrift caches stage-2 responses on disk at
`<XDG_CACHE_HOME>/bomdrift/osv/<advisory_id>.json` with a 24h TTL.

```
~/.cache/bomdrift/osv/
├── CVE-2025-12345.json
├── GHSA-3p68-rc4w-qgx5.json
└── MAL-2026-2306.json
```

Each cache file looks like:

```json
{
  "fetched_at": 1745878800,
  "severity": "Critical",
  "raw": { ... full /vulns/{id} response ... }
}
```

### Cache behavior

- **Cache hits log nothing.** A successful 24h-fresh hit is silent.
- **Cache misses are silent too.** Each miss issues a network fetch
  and writes the result on success.
- **End-of-run summary.** A single line goes to stderr like
  `osv: 18/22 severities served from cache` so CI logs show the cache
  hit ratio without per-file noise.
- **Atomic writes.** Cache files are written to `<id>.json.tmp` then
  renamed, mirroring the temp-file + rename pattern used by
  `bomdrift refresh-typosquat`.
- **Stale TTL.** 24h is a deliberate balance between rerun friction
  (a CI job re-running 30 minutes after the last one wants the cache)
  and stale-severity risk (a published severity correction after 24h
  is rare and the renderer's contract is "best effort").

### `--no-osv-cache`

For paranoid reruns where you want fresh fetches even within the 24h
window:

```bash
bomdrift diff before.json after.json --no-osv-cache
```

The cache itself is purely an optimization — the bypass flag always
works, it just costs N+1 fetches per run. Use sparingly.

## `--no-osv` (offline mode)

Skip the entire OSV pipeline (both stages, no cache writes). Use for:

- Tests and example scenarios where determinism matters more than
  freshness.
- Air-gapped CI environments.
- Quick smoke tests of the change-shape signals without the network
  latency.

```bash
bomdrift diff before.json after.json --no-osv
```

## Severity → `--fail-on` mapping

| Threshold | Trips when... |
|---|---|
| `none` | Never. |
| `cve` | Any vuln finding present (regardless of severity). |
| `critical-cve` | Any finding with `severity >= High` (covers HIGH and CRITICAL). |
| `typosquat` | Any typosquat finding; OSV findings do not trip it. |
| `license-change` | Any same-version license change; OSV findings do not trip it. |
| `any` | Any finding of any kind, plus license-changed-without-version-bump. |

The `critical-cve` name covers HIGH-or-CRITICAL because CRITICAL alone
is rare in the GHSA tagging and many actively-exploited advisories ship
as HIGH. The threshold name stays stable; the threshold value covers
the actionable bucket.

## Network behavior

- **Per-request timeout**: 15 seconds.
- **No authentication**: OSV.dev's `/v1/querybatch` and `/v1/vulns/{id}`
  endpoints are both unauthenticated public APIs.
- **User-Agent**: `bomdrift/<version>` so the OSV team can attribute
  traffic if needed.
- **Failures warn and continue**: a network mishap (DNS, timeout, 5xx)
  emits a single stderr warning and the diff renders without the
  Vulnerabilities section. The exit code remains 0 unless `--fail-on`
  was set and a previously-cached vuln tripped it.

## Why OSV.dev specifically?

- **Cross-ecosystem unification.** OSV merges npm advisories from GHSA,
  PyPI advisories from PyPA, Cargo advisories from RustSec, Maven
  advisories from GHSA, etc. into a single API, so bomdrift doesn't
  need ecosystem-specific clients.
- **Open API, no key required.** Every consumer of the `/v1/querybatch`
  endpoint gets the same data without registration overhead.
- **Public schema.** The response shape is documented at
  [ossf.github.io/osv-schema/](https://ossf.github.io/osv-schema/), so
  bomdrift can reason about the shape without depending on an API
  client crate that drags in tokio.
