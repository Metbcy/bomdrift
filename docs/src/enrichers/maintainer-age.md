# Maintainer age signal

Flag newly added GitHub-hosted dependencies whose top contributor's first
commit is suspiciously recent. **The xz/Jia Tan pattern.**

## Why it matters

The xz-utils backdoor (CVE-2024-3094, Mar 2024) was the work of "Jia Tan",
a GitHub identity that started contributing roughly two years before
landing the malicious payload. The pattern — a brand-new account
becoming the de facto sole maintainer of a low-traffic but
widely-depended-upon package — is a leading indicator of long-game
supply-chain takeovers.

We can't catch Jia Tan in retrospect, but we can flag the *next* one
earlier in their arc by surfacing "this package's top contributor opened
their first PR less than 90 days ago" at the moment a new dep is added.

## Threshold

**90 days.** Intentionally aggressive: most legitimate new packages will
trip this on initial introduction. That's fine — a human reviewer can
dismiss "the package is brand-new and the author is its only maintainer"
trivially.

The expensive miss is the **silent takeover** of an existing package by
a recently-arrived contributor, which is what the 90-day window
captures. Tune later if the false-positive rate is unworkable in
practice.

## How it works

For each `cs.added` component with a GitHub `source_url`:

1. **GET `/repos/{owner}/{repo}/contributors?per_page=1`** — top
   contributor login.
2. **GET `/repos/{owner}/{repo}/contributors`** to count contributors.
   **Skip if > 50** — "top contributor joined recently" loses meaning
   when 200 people have committed (Linux, Kubernetes, React, etc.).
3. **GET `/repos/{owner}/{repo}/commits?author=<login>&per_page=1`** to
   find the most recent commit by that author.
4. **Paginate to the last page** to find their *first* commit. The
   "first commit by author" pagination trick is slow on prolific
   contributors (last page can be page 50+) but is correct without
   needing the GraphQL API.
5. **Compare against the SBOM-after timestamp** (or `Utc::now()` when
   the SBOM lacks a metadata timestamp). Flag when the first commit
   is younger than `YOUNG_MAINTAINER_DAYS = 90`.

## Skipped cases

- Components without a `source_url` (CycloneDX `externalReferences`
  with no `vcs` entry, etc.) — silently skipped.
- Non-`github.com` source URLs — silently skipped (GitLab / Codeberg
  / etc. would need per-host clients; out of scope for v0).
- Repositories with **> 50 contributors** — skipped because the "top
  contributor's first commit" loses meaning on monorepos and
  multi-vendor projects.
- Repositories returning 404 or 403 — skipped, warned once.

Per-repo results are cached within a single bomdrift run so repeated
`cs.added` entries from the same project don't re-issue the same three
requests.

## Network behavior

- **Per-request timeout**: 15 seconds.
- **`GITHUB_TOKEN` honored**: bumps the unauthenticated 60/hr cap to
  the authenticated 5000/hr cap. Without a token, large diffs (~30+
  added GitHub deps) will hit rate-limiting; surface as a warning,
  partial results render, exit code stays 0.
- **No `octocrab`**: the `octocrab` crate would pull in tokio + ~70
  transitive crates. Hand-rolled `ureq` GETs + a 25-line ISO-8601
  parser keep the bomdrift binary under our 5 MB target.

## `--no-maintainer-age`

Skip the entire enricher (no GitHub API calls). Required for:

- Offline runs and tests.
- CI environments where `GITHUB_TOKEN` is unset and the
  unauthenticated rate limit (60/hr) is too low for the diff being
  analyzed.
- Smoke tests of the deterministic offline signals.

```bash
bomdrift diff before.json after.json --no-maintainer-age
```

## Severity

Always informational. The maintainer-age signal **never** trips
`--fail-on critical-cve`; it surfaces only under `--fail-on any`. The
intent is for human review, not gating: many legitimate packages have
brand-new authors, and the 90-day threshold is calibrated to surface
the xz-style pattern, not to fail the build automatically.

## Calibration roadmap

The 90-day threshold is the v0.3 default. Future calibration possibilities:

- **Tunable threshold flag** — `--maintainer-age-days <N>`. Trivial to
  add; gated on someone wanting it (issue welcome).
- **Multi-signal fusion** — combine maintainer-age with "package has
  zero downloads" or "package was published yesterday" to narrow the
  false-positive rate.
- **GraphQL pagination** — replace the REST `last-page` trick with a
  GraphQL query that returns the first commit's date directly. Cuts
  one round-trip per component but adds a token requirement (the
  GraphQL endpoint always wants auth).

See [Roadmap](../roadmap.md) for the current backlog.
