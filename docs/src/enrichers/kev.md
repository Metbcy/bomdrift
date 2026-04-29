# CISA KEV

bomdrift downloads the [CISA Known Exploited Vulnerabilities catalog] and
flips a `KEV` flag on every advisory whose primary id or aliases include a
CVE listed in the catalog.

CISA KEV is the highest-confidence "actively exploited in the wild" signal
available — CISA only adds CVEs to the catalog after observing real-world
exploitation. It's a tighter filter than `--fail-on critical-cve` (which
fires on CVSS High or above regardless of exploitation evidence).

## Output

- **Markdown**: bold `**KEV**` badge after the severity / EPSS label.
- **Terminal**: plain `KEV` token.
- **JSON**: `enrichment.vulns[purl][i].kev` boolean field.
- **SARIF**: `properties.kev: true` on `bomdrift.cve` results when set.

## Threshold gating

```bash
bomdrift diff before.json after.json --fail-on kev
```

Exits 2 when any advisory has its KEV flag set. `--fail-on any` also
includes KEV.

## Disabling

```bash
bomdrift diff before.json after.json --no-kev
```

or in `.bomdrift.toml`:

```toml
[diff]
no_kev = true
```

## Caching

24h TTL on the bulk catalog JSON at
`<XDG_CACHE>/bomdrift/kev/catalog.json`. Once-daily refresh matches CISA's
publication cadence.

## Best-effort

Network failure logs at `BOMDRIFT_DEBUG=1` and the diff renders with KEV
flags absent. A stale catalog (within the 24h window) is preferred over
re-fetching on every run.

[CISA Known Exploited Vulnerabilities catalog]: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
