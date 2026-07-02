# Multi-major version jumps

Pure-compute, no network, no new dependencies. The version-jump
heuristic flags dependency upgrades that cross **two or more** major
versions in a single diff (e.g. `1.x → 4.x`).

## Why this signal

A single major bump (`1 → 2`) is the standard SemVer signal reviewers
already pay attention to, and bomdrift does not flag it. **Two or more
majors at once** is the unusual case worth a closer look:

- **Takeover swaps**: a maintainer transition followed by a major-version
  rename to "reset" the package identity (the xz pattern, scaled down).
- **Namespace reuse**: an unrelated package republished at a higher
  major under the same name, intentionally or after an account
  compromise.
- **"Cleaned up the dep tree" PRs**: legitimate but high-risk refactors
  that silently jump several majors at once and bypass the usual SemVer
  guard-rails.

## Algorithm

Major-version extraction is hand-rolled, ~5 lines. We deliberately avoid
the `semver` crate: full SemVer parsing is unnecessary when only the major
number is consulted, and pulling the dep would add transitive weight for
no functional gain. A pair is flagged when both versions parse to a major
and the delta is at or above the threshold (default 2).

### Accepted forms (each yields a `Some(major)`)

- `1.2.3` → 1
- `v1.0.0` → 1 (leading `v` tolerated)
- `2.5.3-beta.1` → 2 (pre-release suffix ignored)
- `3.0.0+build.123` → 3 (build metadata ignored)
- `4` / `4-rc.1` → 4 (no minor required)

### Rejected forms (yield `None`, the pair is skipped, never flagged)

- empty string
- non-numeric (`latest`, `nightly`, `main`)
- leading-zero numbers (`01.2.3`), ambiguous and almost always a sign
  of a non-SemVer scheme; safer to skip than misinterpret.

### Examples

| Before | After | Flagged? |
|---|---|---|
| `1.0.0` | `4.17.21` | yes (1 → 4) |
| `2.34.0` | `4.5.0` | yes (2 → 4) |
| `1.0.0` | `2.0.0` | no (single major bump) |
| `1.0.0` | `1.99.0` | no (no major bump) |
| `latest` | `nightly` | no (skipped, non-numeric) |
| `01.2.3` | `04.0.0` | no (skipped, leading-zero ambiguity) |

See [`examples/version-jumps/`](https://github.com/Metbcy/bomdrift/tree/main/examples/version-jumps)
for a runnable scenario.

## Threshold

The multi-major delta threshold is `2` by default, exposed via
[`--multi-major-delta <N>`](../cli-reference.md#--multi-major-delta-n)
(introduced in v0.9.7); see [Calibration](#calibration). Findings are
always informational severity and never trip `--fail-on` thresholds
narrower than `any`.

## Output

A flagged pair surfaces in the rendered diff naming the component and the
before/after majors (e.g. `1 → 4`). The finding is informational and
carries no severity gate of its own.

## Network

This signal is pure local computation and never touches the network.

## Disabling

There is no `--no-version-jump` flag, the check is pure compute and zero
cost. If you need to gate exit code only on version-jump findings, use
`--fail-on any`. To suppress a specific bump as a known-acceptable, write
a per-component baseline entry; see
[Baseline — When the bump is the false positive](../baseline.md#when-the-bump-is-the-false-positive).

## Calibration

The multi-major delta threshold is exposed as
[`--multi-major-delta <N>`](../cli-reference.md#--multi-major-delta-n)
(introduced in v0.9.7) with the matching `[diff] multi_major_delta`
config key. Default `2`; minimum `1`.

**Raising** the threshold to `3` or higher quiets noisy ecosystems that
release majors aggressively (some npm web frameworks ship a major every
few months). The signal still fires for genuinely unusual jumps but
stops competing with everyday upgrades for reviewer attention.

**Lowering** to `1` is supported but discouraged: it duplicates the
standard SemVer-bump signal reviewers already see on every PR, and
drowns the multi-major signal's actual purpose (catching the xz pattern
and namespace-reuse swaps). bomdrift validates `>= 1` so `0` is
rejected at the clap layer rather than silently disabling the enricher.

For per-component carve-outs use a baseline entry instead of dropping
the global threshold; see
[Baseline — When the bump is the false positive](../baseline.md#when-the-bump-is-the-false-positive).

## See also

- [Baseline & suppression](../baseline.md#when-the-bump-is-the-false-positive)
- [CLI reference: `--multi-major-delta`](../cli-reference.md#--multi-major-delta-n)
- [Enrichers overview](./overview.md)
