# EPSS

bomdrift queries the [Exploit Prediction Scoring System (EPSS)] from
FIRST.org for every CVE-aliased advisory and surfaces the per-CVE score
(0.0 – 1.0) in markdown / terminal / SARIF output.

## Why this signal

EPSS estimates the probability that a given CVE will be exploited in the
next 30 days. Combined with severity it gives reviewers a sharper signal
than CVSS alone: a Critical CVE with EPSS 0.01 is far less urgent than a
Medium CVE with EPSS 0.85.

## Algorithm

For every CVE-aliased advisory surfaced by the [OSV.dev CVE lookup](./osv-cve.md),
bomdrift fetches the EPSS score from FIRST.org and attaches it to the
finding. When an advisory is keyed by GHSA but has CVE aliases, the score
is the **max across all CVE aliases**, so a GHSA covering two CVEs
surfaces the worse of the two.

## Threshold

EPSS has no surfacing threshold: every scored advisory shows its score.
The optional gate is `--fail-on-epss <FLOAT>`, which exits 2 when any
advisory has a score at or above the value:

```bash
bomdrift diff before.json after.json --fail-on-epss 0.5
```

0.5 is roughly the top decile of actively-exploited CVEs; tune for your
team's risk appetite.

## Output

- **Markdown**: per-advisory badge `EPSS 0.87` after the severity label.
- **Terminal**: same badge, no markup.
- **JSON**: `enrichment.vulns[purl][i].epss_score` numeric field.
- **SARIF**: `properties.epssScore` on `bomdrift.cve` results.

## Network

- **Source**: FIRST.org `/api/v1/epss`.
- **Caching**: 24h TTL at `<XDG_CACHE>/bomdrift/epss/<cve>.json`. Negative
  results (CVEs FIRST.org returned no score for) are cached to avoid
  re-querying recently-published CVEs that haven't been scored yet.
- **Best-effort**: like every bomdrift enricher, EPSS is best-effort. A
  network failure or a malformed response surfaces a `BOMDRIFT_DEBUG=1`
  stderr note and the diff renders with empty `epss_score` fields. EPSS
  being unreachable is never a reason to block a PR review.

## Disabling

```bash
bomdrift diff before.json after.json --no-epss
```

or in `.bomdrift.toml`:

```toml
[diff]
no_epss = true
```

Both forms skip the FIRST.org HTTP call AND the disk cache lookup.

## Calibration

- `--cache-ttl-hours <N>` (v0.9.6+) overrides the default 24h disk cache
  TTL for the EPSS scores cache.
- `--fail-on-epss <FLOAT>` is the threshold gate; see [Threshold](#threshold).

## See also

- [OSV.dev CVE lookup](./osv-cve.md)
- [CISA KEV](./kev.md)
- [Enrichers overview](./overview.md)

[Exploit Prediction Scoring System (EPSS)]: https://www.first.org/epss/
