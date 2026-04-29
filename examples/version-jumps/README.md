# Example: multi-major version jumps

## What this shows

Three dependencies cross two or more major versions in a single diff:

| Ecosystem | Name      | Before  | After   | Major delta |
|-----------|-----------|---------|---------|-------------|
| npm       | `lodash`  | 1.0.0   | 4.17.21 | 1 → 4       |
| Cargo     | `clap`    | 2.34.0  | 4.5.0   | 2 → 4       |
| PyPI      | `django`  | 3.2.0   | 5.0.0   | 3 → 5       |

A single-major bump (`1.x → 2.x`) is the standard SemVer signal reviewers
already pay attention to — bomdrift does **not** flag it. Two or more
majors at once is the unusual case worth a closer look:

- **Takeover swaps** — a maintainer transition followed by a major-version
  rename to "reset" the package identity (the xz pattern, scaled down).
- **Namespace reuse** — an unrelated package republished at a higher
  major under the same name, intentionally or after an account compromise.
- **"Cleaned up the dep tree" PRs** — legitimate but high-risk refactors
  that silently jump several majors at once and bypass the usual SemVer
  guard-rails.

The heuristic is pure-compute (no network, no `semver` crate) and always
informational — `--fail-on` thresholds never trip on it alone.

## Run it

```bash
bomdrift diff before.json after.json --no-osv --no-maintainer-age
```

## Files

- [`before.json`](./before.json) — `lodash@1.0.0`, `clap@2.34.0`, `django@3.2.0`.
- [`after.json`](./after.json) — same packages bumped past the 2-major-delta threshold.
- [`expected-output.md`](./expected-output.md) — pinned reference output.

## What does NOT trip the heuristic

- `1.0.0 → 2.0.0` — single major bump; standard SemVer signal.
- `1.0.0 → 1.99.0` — 0 major bump.
- `latest → main` / `nightly` — non-numeric majors are skipped (rejected,
  not silently mis-parsed).
- `01.2.3 → 04.0.0` — leading-zero majors are ambiguous and skipped to
  avoid misinterpreting non-SemVer schemes.
