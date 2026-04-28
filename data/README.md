# Top-package lists for typosquat detection

This directory holds per-ecosystem snapshots of "legitimate" package names. At build
time, `build.rs` will compress these and embed the result in the binary; at runtime,
`bomdrift refresh-typosquat` can pull fresher copies into the user's XDG cache.

| File              | Source                                        | Refresh cadence |
|-------------------|-----------------------------------------------|-----------------|
| `npm-top5k.txt`   | npm download counts (libraries.io / npm-rank) | Monthly         |
| `pypi-top5k.txt`  | hugovk/top-pypi-packages                      | Monthly         |
| `crates-top1k.txt`| crates.io `?sort=downloads`                   | Quarterly       |
| `maven-top2k.txt` | mvnrepository.com top-artifacts               | Quarterly       |

Snapshots are populated alongside the v0.1.0 release. Empty until then.
