# License policy

bomdrift can enforce a license allow/deny policy on every newly added or
version-changed component. Distinct from the `License changed` finding
(which detects same-version license drift), this is "the configured
policy says this license isn't allowed."

## Configuration

In `.bomdrift.toml`:

```toml
[license]
allow = ["MIT", "Apache-2.0", "BSD-3-Clause", "ISC"]
deny  = ["GPL-3.0-only", "AGPL-*"]
allow_ambiguous = false
```

Or via CLI flags (override the config block when set, matching the
[GitHub Dependency Review Action] flag names exactly):

```bash
bomdrift diff before.json after.json \
    --allow-licenses MIT,Apache-2.0,BSD-3-Clause \
    --deny-licenses 'GPL-3.0-only,AGPL-*'
```

Both flags accept comma-separated values and may be repeated.

## Matching rules (v0.8 — fail-closed)

| Input | With `allow_ambiguous=false` | With `allow_ambiguous=true` |
|---|---|---|
| Atomic license on `allow` | permit | permit |
| Atomic license on `deny` | **deny** | **deny** |
| Atomic license matching `*`-suffix glob in `deny` (`AGPL-*` ↔ `AGPL-3.0-only`) | **deny** | **deny** |
| Atomic license not on `allow` (when `allow` is non-empty) | **not-allowed** | **not-allowed** |
| Compound expression `(MIT OR GPL-3.0)` | **ambiguous** | permit |
| `NOASSERTION` / `OTHER` / empty | **ambiguous** | permit |

**Deny wins** when a license matches both allow and deny.

Compound SPDX expression evaluation (`(MIT OR Apache-2.0)` against
`allow={Apache-2.0}` resolves to permit) lands in v0.9 via the `spdx`
crate. v0.8 fails closed on every compound expression unless
`allow_ambiguous=true` is set explicitly.

## Threshold gating

```bash
bomdrift diff before.json after.json --fail-on license-violation
```

Exits 2 when any violation is present. `--fail-on any` also includes
license violations.

## Output

- **Markdown**: new "License violations" section before "License
  changed", with ecosystem / name / version / license / matched-rule
  columns.
- **Terminal**: `[LIC]` tag + matched rule per finding.
- **JSON**: `enrichment.license_violations` top-level array.
- **SARIF**: `bomdrift.license-violation` rule + per-finding result with
  stable `partialFingerprints.primaryHash/v1`. See
  [SARIF + Code Scanning](./sarif.md).

## Suppression

License violations honor the standard `--baseline` machinery via the
v0.5 `suppressed_advisories` field. Use a fully-qualified license
identifier (or the SPDX expression as written by the SBOM) as the
suppression key. The v0.8 `expires` + `reason` fields work the same
way.

[GitHub Dependency Review Action]: https://github.com/actions/dependency-review-action
