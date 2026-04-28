# Top-package lists for typosquat detection

This directory holds per-ecosystem snapshots of "legitimate" package names. They
are embedded into the binary at compile time via `include_str!` (see
`src/enrich/typosquat.rs`); `bomdrift refresh-typosquat` will eventually pull
fresher copies into the user's XDG cache, overlaying these baked-in defaults.

| File              | Source                                                                                       | Refresh cadence | Status         |
|-------------------|----------------------------------------------------------------------------------------------|-----------------|----------------|
| `npm-top1k.txt`   | [anvaka/npmrank](https://gist.github.com/anvaka/8e8fa57c7ee1350e3491) most-depended-upon list | Quarterly       | Shipped (1000) |
| `pypi-top5k.txt`  | hugovk/top-pypi-packages                                                                     | Monthly         | Pending        |
| `crates-top1k.txt`| crates.io `?sort=downloads`                                                                  | Quarterly       | Pending        |
| `maven-top2k.txt` | mvnrepository.com top-artifacts                                                              | Quarterly       | Pending        |

## Format

One package name per line, lowercase, no leading numbering. Blank lines and
lines starting with `#` are ignored by the loader (so editorial comments are
fine if needed).

## Refreshing the npm list

```bash
curl -fsSL "https://gist.githubusercontent.com/anvaka/8e8fa57c7ee1350e3491/raw/01.most-dependent-upon.md" \
  | grep -oE '^\s*[0-9]+\. \[[^]]+\]' \
  | sed -E 's/^\s*[0-9]+\. \[([^]]+)\]/\1/' \
  > data/npm-top1k.txt
```

After regenerating, run `cargo test` to confirm the test fixtures
(`crypto-js`, `cross-env`, `react-router`, etc.) still appear in the list.
