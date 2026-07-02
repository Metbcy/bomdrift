# Registry-metadata enrichers (npm / PyPI / crates.io)

bomdrift queries package registries for each newly-added component
(plus npm version-changed components for the maintainer-set check)
and surfaces three kinds of finding:

- **Recently published** — the publish timestamp is within
  `--recently-published-days` (default 14 days). Recent publishes
  correlate with takeover swaps and namespace-reuse attacks.
- **Deprecated** — the package or version is flagged deprecated on
  npm, yanked on PyPI / crates.io, or carries an "Inactive" PyPI
  classifier.
- **Maintainer set changed (npm only)** — the maintainer set listed
  for the new version differs from the maintainer set listed for the
  old version. Classic xz / Jia Tan precursor.

## Why this signal

Recently-published, deprecated, and maintainer-set-changed are the npm
Shai-Hulud-style worm precursors: an attacker republishes a package (often
under a fresh maintainer set) within days of a takeover. Catching the
metadata shift at diff time surfaces the swap before the new version is
installed.

### Why npm-only for maintainer-set-changed?

PyPI and crates.io don't expose a clean "maintainers per version"
view in their public REST API:

- **PyPI**: the `info.maintainer` and `info.author` fields are
  free-text and inconsistent across releases. There's no historical
  record per release.
- **crates.io**: `owners` is package-level, not version-level, so we
  can't tell which owners had publish rights at the time of an
  individual version.

When the upstream APIs gain a per-version maintainer view we'll
extend the enricher; a future-version follow-up.

## Algorithm

For each newly-added component (and npm version-changed components for the
maintainer-set check), bomdrift fetches the package's registry metadata and
evaluates the three checks above.

| Ecosystem | URL | Headers |
|---|---|---|
| npm | `https://registry.npmjs.org/<pkg>` (URL-encoded `@scope/name`) | `User-Agent: bomdrift/<version>` |
| PyPI | `https://pypi.org/pypi/<pkg>/json` | — |
| crates.io | `https://crates.io/api/v1/crates/<name>` | `User-Agent: bomdrift/0.9.0 (https://github.com/Metbcy/bomdrift)` (required by crates.io) |

## Threshold

The recently-published check uses a day threshold (`--recently-published-days`,
default 14). The deprecated and maintainer-set-changed checks are boolean:
a package is flagged or it is not. The exit-2 gates are `--fail-on
recently-published` and `--fail-on deprecated`.

## Output

- **Markdown**: three new sections, "Recently published", "Deprecated
  upstream", "Maintainer set changed (npm)", in the per-category area.
- **JSON**: `enrichment.recently_published`, `enrichment.deprecated`,
  `enrichment.maintainer_set_changed`.
- **SARIF**: rules `bomdrift.recently-published`, `bomdrift.deprecated`,
  `bomdrift.maintainer-set-changed` with stable
  `partialFingerprints.primaryHash/v1`.
- **Calibration** rows (`--debug-calibration`):
  `recently-published|<purl>|<days>|14`,
  `deprecated|<purl>|<message>|any`,
  `maintainer-set-changed|<purl>|<changes>|1`.

## Network

- **Sources**: npm / PyPI / crates.io public APIs (see the table under
  [Algorithm](#algorithm)).
- **Caching**: per ecosystem under
  `<XDG_CACHE>/bomdrift/registry/<eco>/<pkg>.json`, 24-hour TTL, atomic
  temp-file + rename writes. Mirrors the OSV / EPSS / KEV cache shape.
- **Best-effort**: a registry timeout, parse error, or unsupported
  ecosystem returns `Ok` with no findings. Diff rendering NEVER blocks
  on registry responses.

## Disabling

```bash
bomdrift diff before.json after.json --no-registry
```

Disables all three checks at once. Equivalent to `[diff] no_registry =
true` in `.bomdrift.toml`.

The full flag set:

- `--no-registry` skips all three checks.
- `--recently-published-days <N>` (see [Calibration](#calibration)).
- `--fail-on recently-published`, `--fail-on deprecated` are exit-2
  thresholds.

## Calibration

- `--recently-published-days <N>` overrides the default 14-day threshold.
  Set `--recently-published-days 0` to disable that check while keeping
  deprecation / maintainer-set-changed.
- `--cache-ttl-hours <N>` (v0.9.6+) overrides the default 24h disk cache
  TTL for the per-ecosystem registry caches.

## See also

- [Maintainer age signal](./maintainer-age.md)
- [Typosquat detection](./typosquat.md)
- [Enrichers overview](./overview.md)
