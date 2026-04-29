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

The baseline parser is intentionally forgiving about missing fields. v0.2
JSON snapshots (which lacked the per-vuln `severity` field) load against
v0.3 and later with reduced suppression precision: a v0.2 baseline can
suppress a vuln by `(purl, advisory_id)` even when the v0.3 enrichment
has populated severity. New baselines should be regenerated under v0.3+
to capture the full match shape.

The action does **not** yet ship a `baseline:` input — pass `--baseline`
via a custom step that calls the `bomdrift` binary directly. A formal
action input is on the [roadmap](./roadmap.md).

## Workflow integration

A typical CI pattern commits the baseline alongside the source code and
refreshes it after a maintainer reviews and accepts new noise as known
acceptable:

```yaml
- name: Run bomdrift with baseline
  run: |
    ./bomdrift diff before.json after.json \
      --baseline .bomdrift-baseline.json \
      --fail-on critical-cve
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
