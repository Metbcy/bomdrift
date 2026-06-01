# What bomdrift catches that other tools miss

This page takes real, published supply-chain incidents and asks the same
question of each: **at PR-review time, before the incident was a known
CVE, which of bomdrift's signals would have fired — and which would
not?**

The credibility of this page depends on it not over-claiming. Where
bomdrift's signals would not have caught an incident, that is called out
explicitly.

## TL;DR

bomdrift complements pure CVE scanners (Snyk / Trivy / Grype /
OSV-Scanner). Its differentiator is **pre-disclosure signals** —
typosquat, maintainer-age, multi-major version jump, recently-published
registry metadata, license-policy changes — that are visible in the diff
*before* a CVE or GHSA advisory exists.

It is not a reachability scanner, and it does not execute package
tarballs. For those, pair it with the tools called out in the README's
[Pair with…](https://github.com/Metbcy/bomdrift#pair-with) table.

## Case studies

### 1. xz-utils backdoor — CVE-2024-3094 (March 2024)

A ~2.6-year social-engineering campaign culminated in a backdoor in
`xz-utils` 5.6.0 / 5.6.1 by the maintainer "Jia Tan", whose first
commits to the project predated the malicious release by under three
years.

| Signal | Would it have fired? |
|---|---|
| **Maintainer age (`young-maintainer-days`)** | **Yes.** The xz pattern is exactly what this signal is designed for: a maintainer who became active recently (in the project's lifetime) is the one shipping a release. |
| **Multi-major version jump** | No. The jump was 5.4 → 5.6, well within one major. |
| **Typosquat** | No. `xz-utils` is the canonical name. |
| **CVE enrichment (OSV / EPSS / KEV)** | After disclosure, yes. Pre-disclosure: no. |

The maintainer-age signal is the only pre-disclosure flag any tool could
have raised, and bomdrift is the only diff-time tool that implements it
as a first-class signal. **bomdrift does not claim it would have
auto-blocked xz** — the signal raises a flag for human review, which is
all any heuristic can honestly do for a multi-year social-engineering
campaign.

### 2. event-stream / flatmap-stream (November 2018)

The maintainer of the (~2M weekly downloads) `event-stream` npm package
handed publish rights to a new contributor, who shipped `flatmap-stream`
as a runtime dependency containing a payload targeted at the Copay
cryptocurrency wallet.

| Signal | Would it have fired? |
|---|---|
| **Brand-new added dependency** | **Yes.** The diff that pulled `flatmap-stream` in would have shown it as an added component. |
| **Recently-published registry signal** | **Yes.** `flatmap-stream` was a freshly-published package at the time of the malicious release. |
| **Maintainer age** | **Partial.** Applies to `event-stream`'s maintainer handover, which is the upstream root cause. |
| **CVE enrichment** | Post-disclosure only (npm published a security advisory once the payload was identified). |

bomdrift's "added + recently-published + maintainer-change" combination
is the exact shape of this incident. Whether a reviewer would have
acted on the flags is a separate question, but the signals would have
been on the comment.

### 3. ua-parser-js compromise (October 2021)

The `ua-parser-js` maintainer's npm account was compromised; three
malicious versions (`0.7.29`, `0.8.0`, `1.0.0`) were published that
installed a cryptominer and a Windows password stealer.

| Signal | Would it have fired? |
|---|---|
| **Multi-major version jump** | **Yes.** `0.7.x → 0.8.x` and especially `0.8.x → 1.0.x` would have tripped the `multi-major-delta` heuristic on any consumer that rolled forward. |
| **Recently-published registry signal** | **Yes.** The three malicious versions were all freshly-published at the time of consumption. |
| **CVE enrichment** | Post-disclosure only. |
| **Typosquat** | No. `ua-parser-js` is the canonical name. |

This is a case where bomdrift's version-jump heuristic does real work —
the legitimate package's release cadence was much slower than the
0.7 → 1.0 burst that landed during the compromise window.

### 4. colors.js / faker.js — Marak protestware (January 2022)

The maintainer of `colors` (~20M weekly downloads) and `faker` (~2.8M
weekly downloads) shipped versions that intentionally entered an infinite
`zalgo` text loop, breaking thousands of CIs.

| Signal | Would it have fired? |
|---|---|
| **CVE enrichment** | **Yes (eventually).** GitHub Security Advisory `GHSA-xxxxxxxxxx` was assigned, and OSV picked it up. PRs that rolled forward to the bad version after the advisory landed would have flagged. |
| **Recently-published registry signal** | **Yes** during the publish window. |
| **Pre-disclosure heuristics** | **No.** The maintainer was long-tenured, the version bump was within-major, and the package name was not a typosquat. |

This is an **honest miss** for pre-disclosure heuristics. bomdrift would
have caught it post-advisory like every other scanner, but maintainer
protestware on an established package is the exact failure mode that no
diff-time heuristic catches reliably. The honest answer is "wait for the
advisory, then suppress or pin via VEX."

### 5. node-ipc protestware (March 2022)

The `node-ipc` maintainer shipped versions that wiped files on machines
geolocated to Russia or Belarus.

| Signal | Would it have fired? |
|---|---|
| **CVE enrichment** | **Yes (eventually).** GHSA-97m3-w2cp-4xx6 was assigned and propagates through OSV. |
| **Recently-published registry signal** | **Yes** during the publish window. |
| **Pre-disclosure heuristics** | **Partial.** The malicious payload was added in a within-major patch by a long-tenured maintainer; the only diff-time flag pre-advisory would be the recently-published-version signal. |

Same honest assessment as colors.js — bomdrift catches it post-advisory,
not pre-.

## Where bomdrift does not claim to catch incidents

A heuristic-based diff-time scanner cannot honestly claim to catch:

- **Malicious code added by an established maintainer in a within-major
  patch release** (colors.js, node-ipc) before an advisory is issued.
- **Compromises where the malicious version's metadata is
  indistinguishable from a normal release** (e.g. no version-jump, no
  added dependency, no typosquat).
- **Runtime-only payloads** that don't surface in package metadata or
  the dependency graph — bomdrift does not execute install scripts or
  parse tarball contents.

For these classes, pair bomdrift with tools that DO execute install
hooks or sandbox-run packages (the README's
[Pair with…](https://github.com/Metbcy/bomdrift#pair-with) table calls
out the relevant options).

## Signal summary

The dimensions bomdrift adds beyond CVE enrichment, and whether the
five incidents above would have benefited from each:

| Signal | xz | event-stream | ua-parser-js | colors.js | node-ipc |
|---|:---:|:---:|:---:|:---:|:---:|
| Brand-new added dep | — | ✓ | — | — | — |
| Multi-major version jump | — | — | ✓ | — | — |
| Maintainer age (young) | ✓ | partial | — | — | — |
| Typosquat | — | — | — | — | — |
| Recently-published | — | ✓ | ✓ | partial | partial |
| License-policy change | — | — | — | — | — |
| CVE / GHSA (post-disclosure) | ✓ | ✓ | ✓ | ✓ | ✓ |

"✓" = the signal would have fired on the PR that pulled in the
compromised release. "partial" = the signal applies to a related root
cause but is not the primary flag.

## Methodology

These five incidents were chosen because they are all (a) well
documented in public advisories and post-mortems, (b) representative of
distinct attack patterns (long-game social engineering, account
compromise, maintainer handover, protestware), and (c) old enough that
the published timeline is stable.

For each, the "would it have fired" judgement is based on the enricher
implementations in bomdrift v0.9.9:

- **Maintainer age** — `src/enrich/maintainer.rs`, configurable via
  `--young-maintainer-days`.
- **Multi-major version jump** — `src/enrich/version_jump.rs`,
  configurable via `--multi-major-delta`.
- **Typosquat** — `src/enrich/typosquat*`, Jaro-Winkler similarity
  against top-N catalogs per ecosystem.
- **Recently-published** — `src/enrich/registry*`, configurable via
  `--recently-published-days`.
- **CVE enrichment** — OSV.dev API with EPSS / KEV overlays.

**What this page does not include yet:** reproducible fixture SBOMs
that demonstrate each signal firing against a frozen package metadata
snapshot. Building those requires capturing historical npm / OSV
responses at the incident date and committing them under
`tests/fixtures/comparison/`. That is tracked separately — see the
[follow-up tasks](#follow-ups) below.

If you spot a claim on this page that you think is incorrect or
over-stated, please [open an issue](https://github.com/Metbcy/bomdrift/issues/new)
— the credibility of this page matters more than its length.

## Follow-ups

- Capture reproducible fixture SBOMs + frozen registry responses for
  each case study under `tests/fixtures/comparison/`, with a CLI
  invocation per case showing the signal fire.
- Add 2–3 more recent incidents once their post-mortems stabilize
  (Shai-Hulud worm, axios March 2026 compromise).
- Cross-link this page from each enricher chapter under "Real-world
  example."
