# Maintainer age signal

Flag newly added dependencies (GitHub, GitLab, Codeberg) whose top
contributor's first commit is suspiciously recent. **The xz/Jia Tan pattern.**

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

**90 days** by default. Intentionally aggressive: most legitimate new
packages will trip this on initial introduction. That's fine — a human
reviewer can dismiss "the package is brand-new and the author is its
only maintainer" trivially.

The expensive miss is the **silent takeover** of an existing package by
a recently-arrived contributor, which is what the 90-day window
captures. Tune for your environment via `--young-maintainer-days <N>`
or `[diff] young_maintainer_days = <N>` (v0.9.6+); see
[Calibration](#calibration) below.

## How it works

For each `cs.added` component with a `source_url` on a supported host:

### GitHub

1. **GET `/repos/{owner}/{repo}/contributors?per_page=1`** — top
   contributor login.
2. **GET `/repos/{owner}/{repo}/contributors?per_page=1&anon=true`** —
   contributor count from Link `rel="last"` page number. **Skip if > 50.**
3. **GET `/repos/{owner}/{repo}/commits?author=<login>&per_page=1`** —
   paginate to last page for the author's oldest commit (`commit.author.date`).

### GitLab

1. **GET `/api/v4/projects/{url-encoded}/repository/contributors?order_by=commits&sort=desc&per_page=1`** —
   top contributor name (GitLab identifies contributors by author name, not
   login) and total count via `X-Total` header. **Skip if > 50.**
2. **GET `.../commits?author=<name>&per_page=1`** — paginate to last page
   via Link header for the author's oldest commit (`authored_date`).

### Codeberg

URL parsing and dispatch are implemented. The per-author first-commit
lookup is stubbed pending verification of the Forgejo v1.20+ API shape;
Codeberg components produce no finding in this release.

## Skipped cases

- Components without a `source_url` (CycloneDX `externalReferences`
  with no `vcs` entry, etc.) -- silently skipped.
- Source URLs not from `github.com`, `gitlab.com`, or `codeberg.org` --
  silently skipped.
- Repositories with **> 50 contributors** -- skipped because the "top
  contributor's first commit" loses meaning on monorepos and
  multi-vendor projects.
- Repositories returning 404, 401, or 403 -- skipped silently (private
  repo or missing token).

Per-repo results are cached within a single bomdrift run so repeated
`cs.added` entries from the same project don't re-issue the same three
requests.

## Network behavior

- **Per-request timeout**: 15 seconds.
- **Token env vars**: `GITHUB_TOKEN` (Bearer), `GITLAB_TOKEN`
  (PRIVATE-TOKEN), `CODEBERG_TOKEN` (Authorization: token). All optional;
  missing token means unauthenticated requests (fine for low volume).
  `GITHUB_TOKEN` bumps the unauthenticated 60/hr cap to 5000/hr.
- **No `octocrab`**: the `octocrab` crate would pull in tokio + ~70
  transitive crates. Hand-rolled `ureq` GETs + a 25-line ISO-8601
  parser keep the bomdrift binary under our 5 MB target. Same
  constraint applies to the GitLab and Codeberg paths.

## Calibration

`--young-maintainer-days <N>` (CLI; v0.9.6+) or `[diff]
young_maintainer_days = <N>` in `.bomdrift.toml` overrides the 90-day
default. Must be `>= 1`.

Recommended ranges:

- `30`–`60` for paranoid security-sensitive monorepos.
- `90` (default) for general-purpose use; the calibration target for
  the xz pattern.
- `180` for ecosystems with high contributor churn where the default
  surfaces too many legitimate first-time-author packages.

The threshold also appears in `--debug-calibration` rows so collected
samples can guide tuning:

```
maintainer-age|<purl>|<days_since_first_commit>|90
```

## Disabling

`--no-maintainer-age` skips the entire enricher (no GitHub, GitLab, or
Codeberg API calls). Required for:

- Offline runs and tests.
- CI environments where tokens are unset and unauthenticated rate
  limits are too low for the diff being analyzed.
- Smoke tests of the deterministic offline signals.

```bash
bomdrift diff before.json after.json --no-maintainer-age
```

## Severity

Always informational. The maintainer-age signal **never** trips
`--fail-on critical-cve`; it surfaces only under `--fail-on any`. The
intent is for human review, not gating: many legitimate packages have
brand-new authors, and the threshold is calibrated to surface the
xz-style pattern, not to fail the build automatically.

## Calibration roadmap (v0.9.6+ status)

Past calibration backlog and how each item resolved:

- **Tunable threshold flag** — *shipped in v0.9.6* as
  `--young-maintainer-days <N>`. See [Calibration](#calibration) above.
- **Multi-signal fusion** — combine maintainer-age with the registry
  enricher's "recently-published" or "maintainer-set-changed" findings
  to narrow the false-positive rate. The signals all surface in the
  same diff today; explicit fusion in a single composite finding is a
  v1.0 follow-up.
- **GraphQL pagination** — *decided not to pursue.* Adds a token
  requirement (the GraphQL endpoint always wants auth) for one
  saved round-trip per component. The `last-page` REST trick is
  documented as the canonical approach; see the module doc-comment in
  `src/enrich/maintainer.rs` for the rationale.

See [Roadmap](../roadmap.md) for the current backlog.
