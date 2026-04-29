# bomdrift + GitLab CI

Drop-in templates for running bomdrift on GitLab MRs. Two files:

- [`.gitlab-ci.yml`](./.gitlab-ci.yml) — runs on every MR pipeline,
  posts the diff as an upserted MR note.
- [`suppress.gitlab-ci.yml`](./suppress.gitlab-ci.yml) — companion
  manual job that takes an advisory ID and commits the suppression to
  the MR branch (analog of the v0.5 GitHub `/bomdrift suppress`
  comment, but triggered from the pipeline view in v0.7).

## Quickstart

1. Copy `.gitlab-ci.yml` to your project root (or `include:` it from a
   shared CI repo).
2. Create a Project Access Token with the `api` scope. Add it as a
   masked CI/CD variable named `BOMDRIFT_API_TOKEN`. (`CI_JOB_TOKEN`
   does **not** work for posting MR notes — its scope is read-only on
   most instances.)
3. Push an MR. The `bomdrift:diff` job runs, generates SBOMs with Syft
   for the merge-base and the MR head, renders the diff to markdown,
   and posts a note marked `<!-- bomdrift:diff -->`. Subsequent pushes
   update the same note.

## Optional: enable suppressions

1. Copy `suppress.gitlab-ci.yml` alongside the diff template (or
   merge its job into your main `.gitlab-ci.yml`).
2. Create a second Project Access Token with the `api` and
   `write_repository` scopes; expose it as `BOMDRIFT_PUSH_TOKEN`.
3. From the MR's pipeline view, run the manual `bomdrift:suppress` job
   with `BOMDRIFT_SUPPRESS_ID=<GHSA-id>`. The job commits the
   suppression to `.bomdrift/baseline.json` on the MR branch; the next
   `bomdrift:diff` run sees the finding as suppressed.

## Why two tokens?

Splitting "post a comment" from "push to a branch" lets you give the
diff job a low-blast-radius token (read + comment) and gate the
push-back-to-branch capability behind a second token reviewers have to
opt in to. If a future bomdrift CVE involves the suppression flow, the
diff path keeps working with no token rotation.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `BOMDRIFT_API_TOKEN not set` warning, no MR note | Token variable missing or scoped to a protected branch only | Re-add the variable; uncheck "Protected" if the MR is from an unprotected branch. |
| 401 from `${CI_API_V4_URL}/projects/.../notes` | Token lacks `api` scope, or it's a `CI_JOB_TOKEN` | Use a Project Access Token, not the job token. |
| `cosign: signature verification failed` | Runner image lacks cosign or can't reach Sigstore | Set `BOMDRIFT_VERIFY_SIGNATURES: "false"` (documented escape hatch); only use this on a runner image you control. |
| `git push` 403 from suppression job | `BOMDRIFT_PUSH_TOKEN` lacks `write_repository`, or the head branch is protected | Reissue the token with `write_repository`; if the branch is protected, allow merge access for the token's user / group. |
| MR note has no styling | GitLab's MR-note markdown subset doesn't support every GitHub flavor (e.g. some `<details>` nuances) | Expected — bomdrift's renderer is the same shape as on GitHub; GitLab's renderer handles 95% of it. |

## Self-Managed GitLab notes

The template uses `CI_API_V4_URL` (auto-populated on every job) instead
of hardcoding `gitlab.com/api/v4`, so it works against Self-Managed
instances unchanged. If your instance restricts outbound traffic to
GitHub Releases (where the bomdrift binary lives), mirror the release
archives to your internal Nexus/Artifactory and override the URL in
the `bomdrift:diff` job:

```yaml
variables:
  BOMDRIFT_RELEASE_BASE_URL: "https://nexus.example.com/repository/bomdrift"
```

(then edit the `curl` line in the script to use this base URL).

## What v0.7 does NOT ship for GitLab

- **In-comment suppression via note webhook** — deferred to v0.8.
  GitLab's note webhook fires on every comment on every MR with no
  command-prefix filter; wiring it safely (debouncing, fork-MR safety,
  command parsing) is non-trivial and the v0.7 manual job covers the
  same need without standing up a webhook handler.
- **`comment-size-limit` MR-note fallback** — the GitHub Action's v0.3
  `--summary-only` fallback for >65k bodies hasn't been ported because
  GitLab's note size cap is much higher (1MB by default). Open an
  issue if you hit the cap.
