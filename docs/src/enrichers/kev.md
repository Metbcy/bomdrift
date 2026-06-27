# CISA KEV

bomdrift downloads the [CISA Known Exploited Vulnerabilities catalog] and
flips a `KEV` flag on every advisory whose primary id or aliases include a
CVE listed in the catalog.

## Why this signal

CISA KEV is the highest-confidence "actively exploited in the wild" signal
available: CISA only adds CVEs to the catalog after observing real-world
exploitation. It's a tighter filter than `--fail-on critical-cve` (which
fires on CVSS High or above regardless of exploitation evidence).

## Algorithm

bomdrift fetches the bulk catalog once, then flips a boolean `KEV` flag on
every advisory (from the [OSV.dev CVE lookup](./osv-cve.md)) whose primary
id or CVE aliases appear in the catalog.

## Threshold

KEV is a boolean flag, not a scored threshold: an advisory either is in the
catalog or it is not. The optional gate is `--fail-on kev`, which exits 2
when any advisory has its KEV flag set:

```bash
bomdrift diff before.json after.json --fail-on kev
```

`--fail-on any` also includes KEV.

## Output

- **Markdown**: bold `**KEV**` badge after the severity / EPSS label.
- **Terminal**: plain `KEV` token.
- **JSON**: `enrichment.vulns[purl][i].kev` boolean field.
- **SARIF**: `properties.kev: true` on `bomdrift.cve` results when set.

## Network

- **Source**: CISA known-exploited catalog (one bulk JSON download).
- **Caching**: 24h TTL on the bulk catalog JSON at
  `<XDG_CACHE>/bomdrift/kev/catalog.json`. Once-daily refresh matches
  CISA's publication cadence.
- **Best-effort**: a network failure logs at `BOMDRIFT_DEBUG=1` and the
  diff renders with KEV flags absent. A stale catalog (within the 24h
  window) is preferred over re-fetching on every run.

## Disabling

```bash
bomdrift diff before.json after.json --no-kev
```

or in `.bomdrift.toml`:

```toml
[diff]
no_kev = true
```

## Calibration

- `--cache-ttl-hours <N>` (v0.9.6+) overrides the default 24h TTL for the
  catalog file via the unified cache-TTL knob. Lower it for faster
  CISA-update propagation in long-running self-hosted runners; raise it
  when running offline or against archived SBOMs.

## See also

- [OSV.dev CVE lookup](./osv-cve.md)
- [EPSS](./epss.md)
- [Enrichers overview](./overview.md)

[CISA Known Exploited Vulnerabilities catalog]: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
