# Example: --baseline suppression

## What this shows

Adopting bomdrift on a project with pre-existing findings risks drowning the
first PR comment in noise that's already been reviewed and accepted. The
`--baseline <path.json>` flag fixes that: bomdrift loads a previously
captured `bomdrift diff --output json` snapshot and suppresses any finding
whose match key is already present.

This example reuses the same SBOM pair as
[`examples/axios-incident/`](../axios-incident/), but adds a baseline that
already records the `plain-crypto-js` typosquat. With the baseline applied,
the rendered output omits the **Possible typosquats** section entirely —
the underlying change rows (Added / Removed / Version changed) still appear,
since `--baseline` only suppresses **findings**, not the diff itself.

## Match keys

bomdrift's match keys per finding type are intentionally conservative — a
finding at a different version than baseline still surfaces:

- **Vulnerabilities**: `(purl_with_version, advisory_id)` — a new
  GHSA against the same component still fires; a new version of the
  same component drops the suppression.
- **Typosquats / version-jumps / maintainer-age**: `(purl_with_version)`
  — same component+version, suppressed.

## Run it

```bash
# Re-generate the baseline against this fixture pair (already pinned in
# baseline.json):
bomdrift diff before.json after.json \
  --no-osv --no-maintainer-age \
  --output json > baseline.json

# Now run the normal diff with the baseline applied. Compare the rendered
# output to examples/axios-incident/expected-output.md — the typosquat
# section is gone here.
bomdrift diff before.json after.json \
  --no-osv --no-maintainer-age \
  --baseline baseline.json
```

## Files

- [`before.json`](./before.json) — same pre-incident SBOM as `axios-incident/before.json`.
- [`after.json`](./after.json) — same post-incident SBOM as `axios-incident/after.json`.
- [`baseline.json`](./baseline.json) — JSON snapshot of the diff *with*
  the typosquat finding present, used to suppress it on subsequent runs.
- [`expected-output.md`](./expected-output.md) — pinned rendered output
  with the baseline applied (no typosquat section).

## Workflow integration

A typical CI pattern is to commit the baseline JSON alongside your code,
and refresh it after a maintainer reviews and accepts the noise as known
acceptable:

```yaml
- uses: Metbcy/bomdrift@v1
  with:
    before-sbom: before.json
    after-sbom:  after.json
    baseline:    .bomdrift/baseline.json   # forthcoming action input
```

Until the action grows a `baseline` input, you can pass `--baseline` via
a custom step that calls the `bomdrift` binary directly. See the
[Docs site](https://metbcy.github.io/bomdrift/) for the full Action input
matrix.
