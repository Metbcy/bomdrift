# Baseline & suppression

The `--baseline <path>` flag suppresses findings that are already present
in a previously captured `bomdrift diff --output json` snapshot. It exists
to make adopting bomdrift on a project with pre-existing findings
practical — the first PR shouldn't drown in noise that's already been
reviewed and accepted.

## How it works

1. Capture a baseline once, after a maintainer has reviewed and accepted
   the current state of findings as known acceptable:

   ```bash
   bomdrift diff before.json after.json --output json > .bomdrift-baseline.json
   ```

   Commit `.bomdrift-baseline.json` to the repo.

2. On subsequent runs, pass `--baseline`:

   ```bash
   bomdrift diff before.json after.json --baseline .bomdrift-baseline.json
   ```

3. Findings whose match key is already present in the baseline are dropped
   from the rendered output **and** from the `--fail-on` trip evaluation.
   New findings — either at a new component, a new version of a known
   component, or a new advisory ID — surface normally.

## Match keys

Match keys are intentionally conservative. A finding at a different version
than baseline still surfaces — version drift is exactly the case where a
known-acceptable finding becomes an unknown one, so suppressing across
versions would defeat the point.

| Finding type | Match key |
|---|---|
| Vulnerability (CVE / GHSA / MAL) | `(purl_with_version, advisory_id)` |
| Typosquat | `(purl_with_version)` |
| Multi-major version jump | `(purl_with_version)` (the after-version) |
| Young maintainer | `(purl_with_version)` |

Notes:

- License-changed-without-version-bump pairs are part of the **ChangeSet**,
  not the enrichment. `--baseline` suppresses *findings*, not the diff
  itself, so license changes always surface in the rendered output. This
  is intentional — a license change at a known version is still a change
  worth a reviewer's eye.
- Vulnerabilities use the advisory ID in the key, so a *new* GHSA against
  an already-known component still fires.
- Typosquats use the after-version in the key, so a typo'd `foo@1.0.0`
  in the baseline doesn't suppress a typo'd `foo@2.0.0`.

## Forward compatibility

The baseline parser is intentionally forgiving about missing fields.
v0.2 baselines can suppress a vuln by `(purl, advisory_id)` even when
the v0.3+ enrichment has populated severity, just with reduced
precision. Regenerate baselines under v0.3+ to capture the full match
shape.

As of v0.4, the action ships a `baseline:` input that plumbs straight
through to `--baseline` — no need for a custom step calling the
binary directly.

## In-comment suppression (v0.5+)

Editing `.bomdrift/baseline.json` by hand on every accepted finding is
friction. v0.5 ships a comment-driven flow: a reviewer comments
`/bomdrift suppress <ADVISORY-ID>` on a PR, and a companion sub-action
appends the ID to the baseline file and commits it to the PR's head
branch. The next bomdrift run on the same PR sees the finding as
suppressed.

### Setup

Add a second workflow alongside your normal bomdrift one:

```yaml
# .github/workflows/bomdrift-suppress.yml
name: bomdrift suppress
on:
  issue_comment:
    types: [created]

permissions:
  contents: write       # to commit the baseline file
  pull-requests: write  # to react on the trigger comment

jobs:
  suppress:
    if: |
      github.event.issue.pull_request &&
      startsWith(github.event.comment.body, '/bomdrift suppress ')
    runs-on: ubuntu-latest
    steps:
      - uses: Metbcy/bomdrift/comment-suppress@v1
```

The `if:` filter is conservative — it gates on both
`github.event.issue.pull_request` (so issue comments don't trigger)
and the comment-body prefix. The sub-action also re-validates both
internally and exits cleanly on non-matching events, so the filter is
defense-in-depth, not load-bearing.

### What it does

1. Parses the comment body for `/bomdrift suppress <id>`. The ID must
   match a GHSA / CVE / MAL pattern.
2. Reacts to acknowledge that the command was accepted.
3. Resolves the PR's head ref via the GitHub API.
4. Downloads the latest bomdrift release archive and (by default)
   verifies its cosign signature.
5. Clones the PR's head branch into a sibling worktree.
6. Runs `bomdrift baseline add <id> --path <baseline-path>`, which
   appends the ID to the `suppressed_advisories` array in the
   baseline file (creating the file if missing).
7. Commits + pushes the baseline change with message
   `chore(bomdrift): suppress <id>`.
8. Reacts on the trigger comment to show success or failure.

### What it suppresses

The v0.5 in-comment flow uses a **wildcard advisory match**: the
specified ID is suppressed across **all** components, not just the
one the comment was attached to. This is intentional — the typical
case is "this advisory is a known false positive in our environment
regardless of which dep pulls it in." For per-component suppression,
hand-edit the baseline using the existing diff-output JSON shape
(see [Match keys](#match-keys) above) — both shapes coexist in the
same file.

### CLI equivalent

The same operation is available from the command line for users who
want to curate a baseline outside CI:

```bash
bomdrift baseline add GHSA-xxxx-yyyy-zzzz
bomdrift baseline add CVE-2026-12345 --path custom/baseline.json
```

The command is idempotent — re-adding an existing ID is a no-op.

### `--from-comment` (v0.9+)

When the GitLab comment-suppress bridge (or any other webhook
handler) hands you a raw note body, pass it via `--from-comment`
and let bomdrift extract the directive:

```bash
bomdrift baseline add --from-comment "Looks fine. /bomdrift suppress GHSA-mwcw-c2x4-8c55 reason: vendor PR #42 already merged"
```

The flag accepts the entire comment body. bomdrift parses the first
`/bomdrift suppress <ID>[ reason: <text>]` line, validates the ID
shape, and either appends the entry (writing object-form when a
reason is present) or exits non-zero with a clear stderr message
when no directive is found. The grammar is identical to the GitHub
`comment-suppress` sub-action — the two parsers are deliberately
kept in lockstep.

## Workflow integration

A typical CI pattern commits the baseline alongside the source code and
refreshes it after a maintainer reviews and accepts new noise as known
acceptable:

```yaml
- uses: Metbcy/bomdrift@v1
  with:
    before-sbom: before.json
    after-sbom:  after.json
    baseline:    .bomdrift/baseline.json
    fail-on:     critical-cve
```

When this fails on a new finding, the maintainer either:

1. **Fixes the finding** (upgrade the dep, replace the typosquat) — no
   baseline change needed.
2. **Accepts the finding** as known acceptable — regenerates the baseline
   and commits it:
   ```bash
   bomdrift diff before.json after.json --output json > .bomdrift-baseline.json
   git add .bomdrift-baseline.json
   ```
   Reviewers see the diff against the previous baseline in the same PR
   and decide whether the new entry is acceptable.

## When NOT to use a baseline

- **For a fresh project.** If you can fix every finding before merging
  the bomdrift integration PR, do that — the baseline is technical debt,
  even if it's debt with a clear purpose.
- **For severity-bucket gating.** Use `--fail-on critical-cve` to gate
  the merge on actionable severity instead of suppressing everything
  under that severity. Baselines are for "we know about this, it's fine
  *for now*", not "ignore this entire class".
- **For findings you'll fix in the next PR.** A baseline is a long-lived
  artifact; for one-PR exceptions, just upgrade the dep.

## Worked example: triaging a false positive

Real-world false positives are the most common reason adopters reach
for the baseline. A typical case looks like this on a PR:

> **🚨 Typosquat candidate** — new dependency `colour-print` is within
> Levenshtein distance 1 of well-known package `colorprint`. Review
> for impersonation.

In our example, `colour-print` is a deliberate British-English spelling
maintained by a long-trusted internal team — this is the canonical
"signal that's true in the abstract, wrong for our codebase" case. The
Levenshtein heuristic *should* fire on this; what's wrong is the
verdict, not the detection. Suppressing the whole `typosquat` class
(via `--fail-on cve`) loses coverage on actually-malicious squats; a
wildcard config field would over-suppress; what we want is exactly
this finding suppressed.

### Step 1 — capture the current finding shape

Before deciding what to suppress, see what bomdrift saw. Run with
`--output json` and pull out the typosquat finding:

```bash
bomdrift diff before.json after.json --output json \
  | jq '.enrichment.typosquat[] | select(.purl | contains("colour-print"))'
```

Output:

```json
{
  "purl": "pkg:npm/colour-print@2.1.0",
  "candidate_for": "colorprint",
  "distance": 1,
  "ecosystem": "npm"
}
```

The `purl_with_version` here is `pkg:npm/colour-print@2.1.0` — the
match key for the typosquat entry per the table above.

### Step 2 — write a per-component baseline entry

Edit `.bomdrift/baseline.json` (the file `bomdrift init` scaffolds, or
whatever path you pass to `--baseline`). The diff-output JSON shape
takes precedence, so a hand-written entry uses the same fields the
JSON output produces:

```json
{
  "suppressed_advisories": [],
  "findings": {
    "typosquat": [
      {
        "purl": "pkg:npm/colour-print@2.1.0",
        "candidate_for": "colorprint",
        "ecosystem": "npm",
        "_note": "British-English spelling, owned by team-foo since 2019. Re-evaluate on major-version bump."
      }
    ]
  }
}
```

The `_note` field is an underscore-prefixed extension; bomdrift
preserves unknown fields verbatim on round-trip and never reads them
back, so it's a safe place to capture the *why*. Future maintainers
who read the baseline see the rationale without spelunking through
git blame.

### Step 3 — verify the suppression takes effect

Re-run the diff with the baseline applied:

```bash
bomdrift diff before.json after.json \
  --baseline .bomdrift/baseline.json
```

The `colour-print` finding is gone; everything else (including any
*other* typosquat candidate that shows up the same week) still
surfaces. That's the trade-off: a precise hand-written entry beats a
wildcard or a class-wide opt-out, because the next typosquat against a
new package still trips the gate.

### Why a hand-edited entry beats `--fail-on` tuning

It's tempting to "just" loosen `--fail-on typosquat` to `--fail-on
critical-cve`. Don't:

- The typosquat enricher is your earliest signal for malicious
  packages — a real squat (`colorize` impersonating `colorise`) is
  caught here before the OSV.dev advisory exists.
- A baseline entry is auditable: `git log .bomdrift/baseline.json`
  shows when this exception was made and by whom.
- A wildcard config setting (e.g., a hypothetical
  `[diff.typosquat] allow_distance_1 = true`) would also suppress
  unrelated future squats. Per-component is the smallest possible
  exception that still fixes this one PR.

### When the bump is the false positive

Sometimes the finding is a multi-major version jump on a package you
*expect* to leap (a calver-style release schedule, a coordinated
ecosystem-wide bump). The same per-component recipe works — replace
the `typosquat` array with `version_jump`, key by the after-version's
`purl`. Update the entry on the next jump.


## Time-boxed suppressions (`expires` + `reason`)

v0.8 adds two optional fields on each `suppressed_advisories` entry:

```json
{
  "suppressed_advisories": [
    {
      "id": "GHSA-evil-1234",
      "purl": "pkg:npm/foo",
      "expires": "2026-12-31",
      "reason": "Awaiting upstream patch (issue #42)"
    },
    "GHSA-old-school"
  ]
}
```

Both fields are optional. String entries (the v0.5 form) keep working —
the array is a union of both shapes.

### Behavior

- **Active entry** (`expires` is today or in the future, OR no `expires`):
  finding is suppressed as before.
- **Expired entry** (`expires` is strictly before today): finding
  surfaces, and bomdrift prints one warning line per expired entry to
  stderr:

  ```
  warning: baseline entry GHSA-evil-1234 (pkg:npm/foo) expired 2026-04-29; finding will surface in this run — was: Awaiting upstream patch (issue #42)
  ```

- **Malformed `expires`** (e.g. `2026/12/31`): bomdrift refuses to load
  the baseline rather than silently treating it as never-expiring. Use
  strict `YYYY-MM-DD` zero-padded.

The "today" comparison honors `SOURCE_DATE_EPOCH` so reproducible-build
contexts stay deterministic.

### CLI

```bash
bomdrift baseline add GHSA-evil-1234 \
  --expires 2026-12-31 \
  --reason "Awaiting upstream patch (issue #42)"
```

The `comment-suppress` companion action also picks up an optional
`reason: <text>` line in the triggering comment body:

```
/bomdrift suppress GHSA-evil-1234
reason: Awaiting upstream patch (issue #42)
```

### Worked rotation example

Six months ago the team accepted GHSA-evil-1234 with a 6-month
expiry. Today the warning fires:

```
warning: baseline entry GHSA-evil-1234 expired 2026-04-29 …
```

The reviewer either renews the suppression (new PR, new expiry +
reason) or removes the entry and merges the upstream patch.
Suppressions become reviewed work-items, not silent forever-state.
