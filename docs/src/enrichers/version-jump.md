# Multi-major version jumps

Pure-compute, no network, no new dependencies. The version-jump
heuristic flags dependency upgrades that cross **two or more** major
versions in a single diff (e.g. `1.x → 4.x`).

## Why it's a useful signal

A single major bump (`1 → 2`) is the standard SemVer signal reviewers
already pay attention to — bomdrift does not flag it. **Two or more
majors at once** is the unusual case worth a closer look:

- **Takeover swaps**: a maintainer transition followed by a major-version
  rename to "reset" the package identity (the xz pattern, scaled down).
- **Namespace reuse**: an unrelated package republished at a higher
  major under the same name, intentionally or after an account
  compromise.
- **"Cleaned up the dep tree" PRs**: legitimate but high-risk refactors
  that silently jump several majors at once and bypass the usual SemVer
  guard-rails.

Always informational severity — never trips `--fail-on` thresholds
narrower than `any`.

## Major-version extraction

Hand-rolled, ~5 lines. We deliberately avoid the `semver` crate: full
SemVer parsing is unnecessary when only the major number is consulted,
and pulling the dep would add transitive weight for no functional gain.

### Accepted forms (each yields a `Some(major)`)

- `1.2.3` → 1
- `v1.0.0` → 1 (leading `v` tolerated)
- `2.5.3-beta.1` → 2 (pre-release suffix ignored)
- `3.0.0+build.123` → 3 (build metadata ignored)
- `4` / `4-rc.1` → 4 (no minor required)

### Rejected forms (yield `None`, the pair is skipped — never flagged)

- empty string
- non-numeric (`latest`, `nightly`, `main`)
- leading-zero numbers (`01.2.3`) — ambiguous and almost always a sign
  of a non-SemVer scheme; safer to skip than misinterpret.

## Threshold

`MIN_MAJOR_DELTA = 2` is the minimum delta to flag. Hardcoded; not
exposed as a CLI flag for two reasons:

1. The signal's whole point is "the standard SemVer signal of a
   single-major bump is already well understood." Letting users
   configure it down to 1 just duplicates the SemVer-bump signal
   reviewers already see.
2. Letting users configure it up (3, 4, ...) would silence legitimate
   xz-pattern signals. The 90-day maintainer-age threshold already
   serves the "tune for false-positive rate" knob.

## Examples

| Before | After | Flagged? |
|---|---|---|
| `1.0.0` | `4.17.21` | yes (1 → 4) |
| `2.34.0` | `4.5.0` | yes (2 → 4) |
| `1.0.0` | `2.0.0` | no (single major bump) |
| `1.0.0` | `1.99.0` | no (no major bump) |
| `latest` | `nightly` | no (skipped — non-numeric) |
| `01.2.3` | `04.0.0` | no (skipped — leading-zero ambiguity) |

See [`examples/version-jumps/`](https://github.com/Metbcy/bomdrift/tree/main/examples/version-jumps)
for a runnable scenario.
