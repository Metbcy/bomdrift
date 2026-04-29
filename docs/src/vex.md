# VEX (Vulnerability Exploitability eXchange)

bomdrift consumes and emits VEX statements so reviewers can record
exploitability decisions next to their SBOMs and have those decisions
suppress noise on subsequent diffs.

Two formats are supported on input (auto-detected per file):

- **OpenVEX 0.2.0** — see <https://github.com/openvex/spec>.
- **CycloneDX VEX 1.6** — `analysis.state` is mapped onto the OpenVEX
  vocabulary (`not_affected` / `resolved` → `not_affected`,
  `exploitable` → `affected`, `in_triage` → `under_investigation`).

OpenVEX is bomdrift's preferred output format on emission (`--emit-vex`)
because the standalone JSON-LD doc is the smallest interop surface.

## Consuming VEX (`--vex <path>`)

The flag is repeatable. Each file is auto-detected by its top-level
shape. Statements match findings by `(vuln_id_or_alias, product_purl)`.

| VEX status            | Effect on the matching finding              |
|-----------------------|---------------------------------------------|
| `not_affected`        | Suppresses (counted in "Suppressed by VEX") |
| `fixed`               | Suppresses                                  |
| `under_investigation` | Annotates with `VEX:under_investigation`    |
| `affected`            | Annotates with `VEX:affected`               |

A VEX statement's `products[]` may be either purl strings or
`{"@id": "pkg:..."}` objects. A versionless statement
(`pkg:npm/foo`) matches every versioned finding-product
(`pkg:npm/foo@1.2.3`); a versioned statement only matches the exact
purl.

### Synthetic finding IDs

bomdrift emits non-CVE findings (typosquats, version-jumps,
maintainer-age, license-violations). To author VEX statements that
suppress them, use the synthetic ID convention:

| Finding kind        | Synthetic ID format                                          |
|---------------------|--------------------------------------------------------------|
| Typosquat           | `bomdrift.typosquat:<purl>:<closest>`                        |
| Version-jump        | `bomdrift.version-jump:<purl>:<before_major>-><after_major>` |
| Maintainer-age      | `bomdrift.young-maintainer:<purl>:<top_contributor>`         |
| License-violation   | `bomdrift.license-violation:<purl>:<license_string>`         |

Example OpenVEX statement suppressing a typosquat finding:

```json
{
  "vulnerability": { "name": "bomdrift.typosquat:pkg:npm/plain-crypto-js@4.2.1:crypto-js" },
  "products": [ { "@id": "pkg:npm/plain-crypto-js@4.2.1" } ],
  "status": "not_affected",
  "justification": "vulnerable_code_not_present",
  "status_notes": "verified the package is a re-export and not impersonating crypto-js"
}
```

### Multiple files

`--vex first.json --vex second.json` is processed left-to-right.
Statements with the same `(vuln_id, product)` are first-write-wins —
later files do NOT override earlier ones. Layer policy-level VEX first
and project-level VEX second so the project-level entries override the
defaults. (Or pass them in the reverse order if you want the opposite
precedence.)

### Verifying with `vexctl`

If you have [vexctl](https://github.com/openvex/vexctl) installed:

```sh
vexctl filter --vex bomdrift.openvex.json sbom.cdx.json
```

verifies the VEX doc is well-formed and that statements match a known
purl in your SBOM.

## Emitting VEX (`--emit-vex <path>`)

Writes a single OpenVEX 0.2.0 document covering every finding in the
post-baseline diff.

- **Baseline-suppressed findings** inherit their `vex_status` from the
  baseline entry, defaulting to `under_investigation`. Baseline ≠
  "not affected" — baseline often means "accepted in PR review" or
  "temporarily ignored", so emitting `not_affected` by default would
  publish a false claim. Opt in by adding `vex_status: "not_affected"`
  to the baseline entry:

  ```json
  {
    "id": "GHSA-x-y-z",
    "purl": "pkg:npm/foo",
    "expires": "2026-12-31",
    "reason": "Awaiting upstream patch (issue #42)",
    "vex_status": "not_affected",
    "vex_justification": "vulnerable_code_not_present"
  }
  ```

- **Un-suppressed findings** emit as `affected` with `status_notes`
  describing the bomdrift finding kind. The justification field falls
  back to the configured
  `[diff] vex_default_justification`
  (default `vulnerable_code_not_in_execute_path`).

The doc's `timestamp` honors `SOURCE_DATE_EPOCH`, so `--emit-vex`
output is byte-deterministic in CI when the env is set.

### Configuration keys

```toml
[diff]
vex_author = "https://example.com/security"
vex_default_justification = "vulnerable_code_not_in_execute_path"
```

`vex_author` falls back to `repo_url` when unset; falls back to
`"bomdrift"` when both are missing.

## Worked rotation example

1. Run a diff that surfaces `GHSA-evil` on `pkg:npm/foo@1.0.0`.
2. Investigate, conclude the vulnerable function is not on your
   execute path.
3. Add the entry to `.bomdrift/baseline.json` with VEX status:

   ```json
   {
     "schema_version": 1,
     "suppressed_advisories": [
       {
         "id": "GHSA-evil",
         "purl": "pkg:npm/foo@1.0.0",
         "expires": "2027-01-01",
         "reason": "Function is unreachable per audit (PR #123)",
         "vex_status": "not_affected",
         "vex_justification": "vulnerable_code_not_in_execute_path"
       }
     ]
   }
   ```

4. Re-run with `--emit-vex bomdrift.openvex.json` to produce a publishable
   exploitability statement that downstream consumers can ingest with
   their own `--vex` flag.
