# Typosquat detection

The typosquat enricher flags newly added components whose names are
suspiciously close to a popular package in the same ecosystem. v0.3 covers
**npm**, **PyPI**, **Cargo**, and **Maven** with rules tuned per ecosystem.

## The signal

Typosquatting is a real and recurring supply-chain attack pattern:

- The 2024 PyPI campaign that registered `colorama-0.4.7` — note the
  trailing zero — to drop a credential stealer.
- The Mar 2026 axios incident's `plain-crypto-js@4.2.1` — a typo of the
  legitimate `crypto-js` — used to exfiltrate via WAVESHAPER.V2.
- Sustained npm `lodash` lookalikes (`loadash`, `loadsh`, `loadshes`)
  through 2024–2026.

The pattern is consistent across ecosystems: a candidate name with high
visual / phonetic similarity to a popular package, often with a single
character substitution / insertion / deletion, sometimes with an added
prefix or suffix. The defender's task is to flag the candidate at PR
review time, before `npm install` or `pip install` runs the malicious
code.

## Algorithm

The core scoring is **Jaro-Winkler similarity** with a **suffix-containment
boost** for the textbook prefix-add pattern (`plain-crypto-js`).
Threshold: **0.92** for a finding to surface. Maven is the exception (see
below).

### Per-ecosystem rules

| Ecosystem | Canonicalization | Separators | Scoring |
|---|---|---|---|
| npm | lowercase | `-`, `_`, `.`, `/` | Jaro-Winkler + suffix boost |
| PyPI | PEP 503 (lowercase, `-`/`_`/`.` collapse) | `-`, `_`, `.` | Jaro-Winkler + suffix boost |
| Cargo | lowercase | `-` | Jaro-Winkler + suffix boost |
| Maven | lowercase | (n/a) | Levenshtein ≤ 2 on `artifactId` only |

#### Filtering rules (npm / PyPI / Cargo)

1. **Exact match (case-insensitive after canonicalization) → skip.** The
   candidate IS a popular package, not a squat.
2. **Likely-legit ecosystem extension → skip.** When the candidate
   starts with the legit name followed by a separator, this matches
   the well-established convention for extension packages
   (`react-router`, `axios-retry`, `eslint-plugin-react`,
   `pytest-asyncio`). The structural rule is keyed on ecosystem-
   specific separator sets so PyPI's `-`/`_`/`.` interchange doesn't
   leak into npm's wider set.
3. **Suffix containment with a substantial added prefix → boost.** When
   the candidate ends with the legit name (length ≥ 5) AND the added
   prefix is longer than 3 characters, the score is boosted to at
   least 0.95. This catches the deceptive `plain-crypto-js` pattern
   that pure JW alone misses (the long prefix kills base similarity).
4. **Otherwise: plain Jaro-Winkler.** Threshold 0.92 catches single-
   character drift like `cross-env → crossenv` (~0.98) or
   `express → expresss` (~0.97), while `react → react-router`
   (~0.88) stays below the threshold.

#### Maven rules

Maven coordinates are `groupId:artifactId`. The shared `groupId` prefix
is often very long (`org.springframework.boot:`,
`com.fasterxml.jackson.core:`) and would inflate Jaro-Winkler past
anything useful — every Spring artifact would score 0.95+ against
every other Spring artifact. The Maven path skips JW + suffix-
containment entirely and uses **Levenshtein distance ≤ 2 on the
`artifactId` portion** only.

`commons-lng3` differs from `commons-lang3` by Levenshtein 1
(insert `a`), so it fires regardless of whether the `groupId` matches.
A different-`groupId` republish of an exact `commons-lang3` artifact
does **not** fire — that's a legitimate fork / republish, not a typo.

## Reputational care

The renderer wording is intentional:

> *X is similar to Y*

— never *X is a typosquat of Y*. Flagging a legitimate package as a
malicious squat in a public PR comment is real reputational harm to
the package author. The structural similarity is observable; intent
is not. The human reviewing the PR is the analyst making the
determination.

The CLI / Action exit code reflects this: typosquat findings are
always informational. `--fail-on typosquat` exists for projects that
want to gate on the structural signal explicitly, but it's never the
default.

## Reference lists

Embedded snapshots ship in the binary:

| File | Source | Size |
|---|---|---|
| `data/npm-top1k.txt` | [anvaka/npmrank](https://gist.github.com/anvaka/8e8fa57c7ee1350e3491) | 1000 |
| `data/pypi-top200.txt` | [hugovk/top-pypi-packages](https://hugovk.github.io/top-pypi-packages/) | 200 |
| `data/cargo-top200.txt` | crates.io API `?sort=downloads` | 200 |
| `data/maven-top100.txt` | mvnrepository.com Most Popular (curated) | ~100 |

The lists are intentionally smaller than `npm-top1k.txt` for the v0.2
ship: the algorithm is identical across ecosystems, so a smaller seed
proves the signal end-to-end. Lists grow in subsequent releases without
code changes — only the embedded snapshot does.

### Refreshing

```bash
bomdrift refresh-typosquat                  # all ecosystems with a wired fetcher
bomdrift refresh-typosquat --ecosystem npm
bomdrift refresh-typosquat --ecosystem pypi
bomdrift refresh-typosquat --ecosystem cargo
```

Refreshed lists are written to
`<XDG_CACHE_HOME>/bomdrift/typosquat/<ecosystem>.txt` via temp-file +
atomic rename. The enricher prefers cache files over the embedded
snapshot when present and parseable.

`--ecosystem maven` is accepted but emits a notice: Maven Central has
no canonical "top N" feed analogous to the others. The curated list
is the source of truth; refreshing means editing
`data/maven-top100.txt` and rebuilding bomdrift.

## False-positive management

The structural rules + thresholds aim for "no false positives on the
top 1000 of each ecosystem." If you discover a false positive in the
wild:

1. Add a regression test in `src/enrich/typosquat.rs::tests` showing
   the false positive doesn't fire.
2. Open a PR. Tightening the rule (rather than special-casing the
   package name) is preferred — drives a cleaner heuristic.

If you discover a false negative (a real typosquat that *should* fire
but doesn't):

1. Same — add a regression test that fires, then tweak the algorithm
   until it does.
