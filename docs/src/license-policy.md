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

## SPDX expression evaluation (v0.9+)

bomdrift evaluates each license string as a full SPDX expression via
the `spdx` crate. Evaluation outcomes:

| Expression | Allow | Deny | Outcome |
|---|---|---|---|
| `MIT` | `[MIT]` | — | Permitted (allow exact match) |
| `(MIT OR Apache-2.0)` | `[MIT]` | — | Permitted (one branch allowed) |
| `(MIT AND GPL-3.0-only)` | `[MIT]` | `[GPL-3.0-only]` | Violation (deny wins) |
| `(GPL-3.0-only OR MIT) AND BSD-3-Clause` | `[MIT, BSD-3-Clause]` | `[GPL-3.0-only]` | Violation (denial path could resolve to GPL) |
| `Apache-2.0 WITH LLVM-exception` | `[Apache-2.0]` | — | Permitted (base license allowed; exception identity is currently informational only) |
| `Custom` (non-SPDX) | `[MIT]` | — | Falls back to atomic match → not in allow list |
| `NOASSERTION` / `OTHER` / empty | `[MIT]` | — | Ambiguous → violation (fail-closed) |

### Precedence

1. **Deny wins** — any required atomic on the deny list (including any
   OR-branch) trips a violation, because the resolved license could be
   the denied alternative.
2. **Glob** — `*` suffix patterns work in both lists (e.g. `AGPL-*`
   matches every `AGPL-*-only` family member).
3. **Allow** — when the allow list is non-empty, the SPDX expression
   must `evaluate` to true under a closure that returns true for
   allow-listed atomics.
4. **Non-SPDX strings** — fall through to the v0.8 atomic-string
   matcher so vendor-specific license strings keep working.

### Deprecated: `allow_ambiguous`

The v0.8 `allow_ambiguous` flag flipped fail-closed behavior on
compound expressions. v0.9's evaluator handles compounds correctly,
so the flag is now a no-op when SPDX parsing succeeds. A one-time
deprecation warning is printed to stderr per run when the flag is
set. The flag still works on the fallback path (non-SPDX strings) for
back-compat; it will be removed in v1.0.

### `WITH` (exception) granularity

Per-exception allow/deny is configured with
[`--allow-exception` / `--deny-exception`](./cli-reference.md#--allow-exception-list--deny-exception-list)
(or `[license] allow_exceptions` / `deny_exceptions` in `.bomdrift.toml`).
When either list is non-empty, the right-hand side of every `WITH`
clause is evaluated against it: `Apache-2.0 WITH LLVM-exception` is
permitted iff `Apache-2.0` passes the base policy AND `LLVM-exception`
is on the allow list (or absent from a non-empty deny list). Empty
exception lists preserve v0.9 behavior — exceptions are informational
only.

#### Compound-expression inheritance (v0.9.7)

v0.9.7 refines how exception decisions propagate through compound
expressions. The rules:

1. **AND inherits**: `(X WITH ex) AND (Y)` denies if **either** sub-clause
   would deny on its own. A denied exception in any conjunct denies the
   whole expression — every required atomic must be satisfiable, so a
   poisoned `WITH` clause poisons the conjunction.
2. **OR does not poison**: `(X WITH ex_a) OR (X WITH ex_b)` is permitted
   when **at least one** branch is permitted. A denied exception on one
   branch doesn't sink the expression as long as another branch
   resolves cleanly.
3. **Bare exception lookup**: `WITH <exception>` without an
   allow/deny exception list configured falls through to v0.9 behavior
   (informational; the base license alone gates).
4. **Deny still wins atomically**: a base license on the deny list
   denies regardless of the exception attached.

##### Worked examples

Assume `[license] allow = ["Apache-2.0", "MIT"]`,
`allow_exceptions = ["LLVM-exception"]`,
`deny_exceptions = ["Classpath-exception-2.0"]`.

| Expression | Resolution | Why |
|---|---|---|
| `Apache-2.0 WITH LLVM-exception` | **permit** | base allowed, exception allowed |
| `Apache-2.0 WITH Classpath-exception-2.0` | **deny** | exception on deny list |
| `Apache-2.0 WITH Some-other-exception` | **deny** | base allowed, but exception not on the non-empty allow list |
| `(Apache-2.0 WITH LLVM-exception) AND BSD-3-Clause` | **deny** | AND inherits — `BSD-3-Clause` not on allow list, denies the conjunction even though the `WITH` half is fine |
| `(Apache-2.0 WITH LLVM-exception) AND MIT` | **permit** | both conjuncts pass independently |
| `(Apache-2.0 WITH Classpath-exception-2.0) AND MIT` | **deny** | denied exception poisons the AND |
| `(Apache-2.0 WITH Classpath-exception-2.0) OR (Apache-2.0 WITH LLVM-exception)` | **permit** | OR doesn't poison — the LLVM branch resolves cleanly |
| `(Apache-2.0 WITH Classpath-exception-2.0) OR (GPL-3.0-only)` | **deny** | both branches denied (one by exception, one by missing-from-allow) |

The runtime evaluator constructs a closure over the allow / deny
exception sets and lets the `spdx` crate's expression-evaluation walk
the tree; the rules above describe the closure's per-leaf decision.
