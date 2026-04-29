# Example: multi-ecosystem typosquat detection

## What this shows

The same Jaro-Winkler + suffix-containment algorithm that catches
`plain-crypto-js → crypto-js` on npm fires across **PyPI**, **Cargo**, and
**Maven** with per-ecosystem rules tuned for each one's naming conventions.

The `before.json` SBOM contains four legitimate top-N packages — one in each
supported ecosystem. The `after.json` adds a typosquat of each, designed to
slip past a casual code review:

| Ecosystem | Legitimate    | Typosquat                       | Detection mechanism                              |
|-----------|---------------|---------------------------------|--------------------------------------------------|
| npm       | `cross-env`   | `crossenv`                      | Jaro-Winkler ~0.98 (single-character drop)       |
| PyPI      | `requests`    | `requessts`                     | Jaro-Winkler ~0.95 after PEP 503 normalization   |
| Cargo     | `serde`       | `serdee`                        | Jaro-Winkler ~0.97 (single-character append)     |
| Maven     | `commons-lang3` | `commons-lng3` (same groupId) | Levenshtein distance 1 on artifactId only        |

All four trip the typosquat enricher in a single offline pass — no network
required.

## Run it

```bash
bomdrift diff before.json after.json --no-osv --no-maintainer-age
```

## Files

- [`before.json`](./before.json) — four legitimate top-N packages, one per ecosystem.
- [`after.json`](./after.json) — same four legits plus four typosquats.
- [`expected-output.md`](./expected-output.md) — pinned reference output.

## Why per-ecosystem rules?

- **npm** uses `-`, `_`, `.`, `/` as separators; `lodash-es` is a legit
  extension of `lodash`, not a squat. The structural rule "candidate starts
  with the legit name followed by a separator" filters those out.
- **PyPI** canonicalizes `-`/`_`/`.` per PEP 503, so `scikit_learn` and
  `scikit-learn` are the same canonical name. Without that, every dash/
  underscore variant of every popular package would false-positive.
- **Cargo** only allows `-` as a separator; the rule narrows to that.
- **Maven** coordinates are `groupId:artifactId`, and the long shared
  `groupId` prefix inflates Jaro-Winkler past anything useful. The Maven
  path skips JW entirely and uses Levenshtein ≤ 2 on the `artifactId`
  portion only — `commons-lng3` differs from `commons-lang3` by one
  character, regardless of whether the `groupId` matches.
