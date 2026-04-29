---
name: False positive (typosquat / version-jump / maintainer-age)
about: A bomdrift signal fired on a finding that's actually safe.
labels: false-positive
---

## Which signal fired

<!-- Pick one. -->

- [ ] Typosquat (`bomdrift.typosquat`)
- [ ] Multi-major version jump (`bomdrift.version-jump`)
- [ ] Young maintainer (`bomdrift.young-maintainer`)
- [ ] CVE / advisory (`bomdrift.cve`)
- [ ] License change (`bomdrift.license-change`)

## What surfaced

```
<!-- paste the relevant section of the bomdrift PR comment here -->
```

## Why it's a false positive

<!-- One or two sentences: how do you know this finding is safe?
e.g. "The maintainer is the same human who's been on the project for 8
years; their account just rotated names." -->

## Repro / minimal SBOM pair

<!-- Optional but extremely helpful. A 5-component synthetic CDX 1.5
or SPDX 2.3 JSON pair that reproduces the finding makes it easy to
add a regression test alongside the fix. -->

## Environment

- **bomdrift version**: `<output of bomdrift --version>`
- **OS / arch**: <e.g. ubuntu-latest x86_64, macos-arm64>
- **Invocation**: <action / standalone CLI / library>

## Anything else

<!-- Suggested rule tightening, links to upstream advisory pages,
notes from the OSV.dev advisory, etc. -->
