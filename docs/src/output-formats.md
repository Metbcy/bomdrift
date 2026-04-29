# Output formats

bomdrift writes one rendered representation of a diff per invocation. The
shape is deterministic — identical inputs produce byte-identical output —
which is what the PR-comment upsert mechanism in the action relies on.

`--output` selects the format. Default is `terminal` when stdout is a TTY,
`markdown` otherwise.

## Markdown

The default for piped/redirected output, designed to drop into a GitHub
PR comment. Renders the diff as a summary table at the top, followed by
per-section tables for each change category and finding type.

```markdown
## SBOM diff

| Change | Count |
|---|---:|
| Added | 1 |
| Removed | 1 |
| Version changed | 1 |
| License changed | 0 |
| Possible typosquats | 1 |

### Added
| Ecosystem | Name | Version |
|---|---|---|
| npm | plain-crypto-js | 4.2.1 |

### Possible typosquats
| Ecosystem | Name | Version | Similar to | Similarity |
|---|---|---|---|---:|
| npm | plain-crypto-js | 4.2.1 | crypto-js | 0.95 |
```

When OSV.dev enrichment is enabled, an additional **Vulnerabilities**
section lists each affected component with its advisory IDs sorted
highest-severity-first within a component (ties broken by ID, so output
stays byte-deterministic).

`--summary-only` emits only the summary table + a footer line. Used by
the action's comment-size fallback for big-PR survival.

## Terminal

ANSI-colored, tree-style output. Default when stdout is a TTY. Falls back
to markdown when stdout is piped/redirected (so action workflows that
capture stdout always see safe markdown). Honors `NO_COLOR` (skip ANSI)
and `CLICOLOR_FORCE` (force ANSI even on a non-TTY).

Findings are rendered with bracketed prefixes:

| Prefix | Meaning |
|---|---|
| `[ADD]` | Added component |
| `[REM]` | Removed component |
| `[VER]` | Version changed |
| `[LIC]` | License changed (same version) |
| `[CVE]` | OSV.dev advisory |
| `[SQT]` | Typosquat |
| `[JMP]` | Multi-major version jump |
| `[YNG]` | Young maintainer |

No emojis — bomdrift's renderers stay strictly bracketed-prefix per
project convention, both for terminal accessibility and for grepability
of CI logs.

## JSON

Pretty-printed `{"changes": ChangeSet, "enrichment": Enrichment}` graph
for downstream tooling, baselines, debugging.

```json
{
  "changes": {
    "added":           [ ... Component objects ... ],
    "removed":         [ ... ],
    "version_changed": [[ before, after ], ... ],
    "license_changed": [[ before, after ], ... ]
  },
  "enrichment": {
    "vulns":          { "<purl>": [{ "id": "...", "severity": "..." }, ...] },
    "typosquats":     [ ... ],
    "version_jumps":  [ ... ],
    "maintainer_age": [ ... ]
  }
}
```

The `Enrichment.vulns` shape is **per-purl, per-advisory severity-tagged**
as of v0.3. v0.2 emitted a flat `Vec<String>` of advisory IDs without
severity — consumers parsing v0.2 output need to migrate. See the
[CHANGELOG](https://github.com/Metbcy/bomdrift/blob/main/CHANGELOG.md#breaking-output-shape)
for the migration note.

JSON output is the canonical format for `--baseline` snapshots: capture
once with `bomdrift diff --output json > baseline.json`, replay with
`bomdrift diff --baseline baseline.json` on subsequent runs to suppress
already-triaged findings.

## SARIF v2.1.0

Suitable for ingestion by GitHub Code Scanning, GitLab Vulnerability
Reports, and any other consumer that speaks SARIF.

### Stable rule IDs

These IDs surface in Code Scanning's UI and are the join key for
suppressions, so they're load-bearing public API once any consumer has
seen a finding. Renaming any of them is a breaking change.

| Rule ID | Source | Maps to |
|---|---|---|
| `bomdrift.cve` | `enrichment.vulns` | one result per `(component, advisory_id)` |
| `bomdrift.typosquat` | `enrichment.typosquats` | one per typosquat finding |
| `bomdrift.version-jump` | `enrichment.version_jumps` | one per multi-major bump |
| `bomdrift.young-maintainer` | `enrichment.maintainer_age` | one per young-maintainer finding |
| `bomdrift.license-change` | `cs.license_changed` | one per license-changed-without-version-bump |

All five rules are always emitted in `tool.driver.rules`, even when the
current diff has zero findings of that kind — Code Scanning consumers
enumerate rules independently of results, so omitting unused rules
confuses the suppression UI.

### Severity mapping

`result.level` maps from the OSV-fetched severity:

- `Critical` / `High` → `level: "error"`
- `Medium` / `Low` / `None` → `level: "warning"`

This is intentionally separate from `--fail-on critical-cve`'s
threshold (which also fires on High); SARIF's three-level model
(`error`/`warning`/`note`) doesn't map 1:1 to OSV's four severity
labels, so the renderer collapses High+Critical into `error` and
everything else into `warning`.

### Locations

SARIF requires `locations` on every result. Since SBOM-derived findings
have no source line numbers, all results project onto a synthetic
`physicalLocation.artifactLocation.uri = "sbom"`, matching the
convention used by `trivy`.

### Determinism

`Enrichment.vulns` is a `HashMap` and its iteration order is
non-deterministic. The SARIF renderer sorts the keys before emission.
Other finding collections are already deterministically ordered Vecs
(their enrichers iterate the BTreeMap-derived ChangeSet order), so
they need no extra sorting. The render-twice-byte-equal regression
test in `src/render/sarif.rs::tests::render_is_pure_byte_deterministic`
guards against future regressions of this contract.
