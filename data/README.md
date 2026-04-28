# Top-package lists for typosquat detection

This directory holds per-ecosystem snapshots of "legitimate" package names. They
are embedded into the binary at compile time via `include_str!` (see
`src/enrich/typosquat.rs`); `bomdrift refresh-typosquat` will eventually pull
fresher copies into the user's XDG cache, overlaying these baked-in defaults.

| File                | Source                                                                                       | Refresh cadence | Status         |
|---------------------|----------------------------------------------------------------------------------------------|-----------------|----------------|
| `npm-top1k.txt`     | [anvaka/npmrank](https://gist.github.com/anvaka/8e8fa57c7ee1350e3491) most-depended-upon list | Quarterly       | Shipped (1000) |
| `pypi-top200.txt`   | [hugovk/top-pypi-packages](https://hugovk.github.io/top-pypi-packages/top-pypi-packages.min.json) by download count | Monthly         | Shipped (200)  |
| `cargo-top200.txt`  | crates.io API `?sort=downloads&per_page=100` (paginated)                                     | Quarterly       | Shipped (200)  |
| `maven-top100.txt`  | Hand-curated from mvnrepository.com "Most Popular" + Sonatype Central download stats         | Ad-hoc          | Shipped (~100) |

Sizes are intentionally smaller than `npm-top1k.txt` for the v0.2 ship: the
core typosquat algorithm is identical across ecosystems, so a smaller seed
list still proves the signal end-to-end. Lists can be expanded in subsequent
releases without code changes — only the embedded snapshot grows.

## Format

One package name per line, lowercase, no leading numbering. Blank lines and
lines starting with `#` are ignored by the loader (so editorial comments are
fine if needed).

For Maven the format is `groupId:artifactId` (one per line); the typosquat
enricher matches Levenshtein ≤ 2 on the `artifactId` portion only — the
shared `groupId` prefix would inflate Jaro-Winkler similarity past anything
useful.

For PyPI, names are stored verbatim (the upstream uses canonical project
names) and PEP 503 normalization (`-`/`_`/`.` collapse, lowercase) is
applied at load time. So `scikit-learn` and `scikit_learn` will both
canonicalize to the same legit-list entry.

## Refreshing the npm list

```bash
curl -fsSL "https://gist.githubusercontent.com/anvaka/8e8fa57c7ee1350e3491/raw/01.most-dependent-upon.md" \
  | grep -oE '^\s*[0-9]+\. \[[^]]+\]' \
  | sed -E 's/^\s*[0-9]+\. \[([^]]+)\]/\1/' \
  > data/npm-top1k.txt
```

## Refreshing the PyPI list

```bash
curl -fsSL "https://hugovk.github.io/top-pypi-packages/top-pypi-packages.min.json" \
  | python3 -c "import json,sys; d=json.load(sys.stdin); print('\n'.join(r['project'] for r in d['rows'][:200]))" \
  >> data/pypi-top200.txt   # then re-add the header comment block
```

## Refreshing the Cargo list

```bash
for page in 1 2; do
  curl -fsSL -H 'User-Agent: bomdrift/0.2.0 (https://github.com/Metbcy/bomdrift)' \
    "https://crates.io/api/v1/crates?sort=downloads&per_page=100&page=$page" \
    | python3 -c "import json,sys; print('\n'.join(c['name'] for c in json.load(sys.stdin)['crates']))"
  sleep 1
done > /tmp/cargo-top200-body.txt
# then prepend the header comment block manually
```

Respect the crates.io rate limit (1 req/sec, polite User-Agent string).

## Refreshing the Maven list

Maven Central does not expose a canonical "top N" feed. The current list is
hand-curated by browsing
[mvnrepository.com's "Most Popular"](https://mvnrepository.com/popular)
categories (Spring, Apache Commons, Jackson, JUnit, logging, HTTP, ORM,
testing) and cross-checking against Sonatype Central download stats.
Adding a name here is an explicit editorial decision; PRs welcome.

## Validation after refresh

After regenerating any list, run `cargo test --release` to confirm the test
fixtures (`crypto-js`, `cross-env`, `react-router`, `requests`, `numpy`,
`pandas`, `serde`, `tokio`, `clap`, `commons-lang3`, `guava`, etc.) still
appear in their respective lists — those are the load-bearing assertions
that prove the snapshot is intact.
