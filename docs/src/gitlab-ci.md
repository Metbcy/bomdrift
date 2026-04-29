# GitLab CI

bomdrift v0.7+ ships first-class GitLab support via a documented
`.gitlab-ci.yml` template plus a `--platform gitlab` CLI flag that
swaps the rendered footer to the GitLab MR-note shape. The template
lives in [`examples/gitlab-ci/`](https://github.com/Metbcy/bomdrift/tree/main/examples/gitlab-ci);
this chapter walks through the moving parts.

## Why a template instead of a custom action

GitLab CI doesn't have a "marketplace action" model; the unit of
reusability is a YAML snippet. A composite GitHub-Action-style binary
would still need a YAML wrapper, so v0.7 ships the YAML directly. You
can `include:` it from a shared CI repo if you run bomdrift across
many projects:

```yaml
include:
  - project: 'platform/ci-templates'
    file:    '/bomdrift/diff.gitlab-ci.yml'
    ref:     main
```

## Quickstart (zero-config, v0.7+)

On an MR pipeline, the template defaults to comparing the merge-base
SHA against the MR head SHA — no manual SBOM wiring needed:

1. Copy [`examples/gitlab-ci/.gitlab-ci.yml`](https://github.com/Metbcy/bomdrift/blob/main/examples/gitlab-ci/.gitlab-ci.yml)
   to your project root.
2. Add `BOMDRIFT_API_TOKEN` as a masked CI/CD variable. The token must
   be a Project Access Token with the `api` scope; `CI_JOB_TOKEN`
   doesn't work (it's read-only on most instances).
3. Push an MR. The `bomdrift:diff` job runs Syft on both refs,
   renders the markdown diff, and posts/upserts an MR note marked
   `<!-- bomdrift:diff -->`.

That's it. No `.bomdrift.toml` required for the default flow; add one
only when you want a repo-pinned policy.

## What the job does

Step-by-step (matches the `bash <<'BOMDRIFT'` block in the template):

1. **Detects arch** (x86_64 / aarch64) and downloads the matching
   `bomdrift-${VERSION}-...musl.tar.gz` from GitHub Releases.
2. **Optionally cosign-verifies** the archive when `cosign` is on
   PATH and `BOMDRIFT_VERIFY_SIGNATURES=true` (default). Falls back
   to a warning when cosign isn't installed; set
   `BOMDRIFT_VERIFY_SIGNATURES=false` to silence the warning on a
   runner image you've pinned manually.
3. **Installs Syft** via the upstream `install.sh`.
4. **Creates two `git worktree`s** — one at the merge-base SHA
   (`CI_MERGE_REQUEST_DIFF_BASE_SHA`), one at the MR head
   (`CI_COMMIT_SHA`). Worktrees share the active checkout's `.git`,
   so this is cheap.
5. **Generates CycloneDX-JSON SBOMs** for both worktrees with `syft
   scan dir:...`.
6. **Runs `bomdrift diff`** with `--platform gitlab`, which renders
   the GitLab-shaped footer (`/-/issues/new?...` plus `bomdrift
   baseline add` hint instead of the GitHub `/bomdrift suppress`
   comment-driven flow).
7. **Posts/upserts the MR note** via the GitLab REST API — finds the
   existing note by the `<!-- bomdrift:diff -->` marker and PATCHes
   it, otherwise POSTs a new one.

The full markdown body is also kept as a job artifact (`diff.md`)
with a 7-day retention so reviewers can recover it after the MR
merges.

## Tokens & permissions

| Token | Scope | Used for |
|---|---|---|
| `BOMDRIFT_API_TOKEN` | `api` | Posting / updating MR notes |
| `BOMDRIFT_PUSH_TOKEN` (optional) | `api` + `write_repository` | Suppression job's commit-back-to-MR-branch step |

Splitting the two tokens means the diff path keeps working even if
the suppression token is rotated, and you can give the diff token a
narrower blast radius. Mark both as **Masked** and as **Protected**
when your default branch is the only place suppression commits should
land.

`CI_JOB_TOKEN` is intentionally not used for the comment path: on
most GitLab instances its scope is read-only, and even where it can
post comments the surface area is wider than what bomdrift needs.

## CLI auto-detection

`bomdrift diff` auto-detects GitLab CI from the environment:

- `GITLAB_CI=true` → flips `--platform` to `gitlab` (unless overridden).
- `CI_PROJECT_URL` → used as `repo_url` (footer link target) when
  `--repo-url` and `BOMDRIFT_REPO_URL` are both unset.

Explicit flags always win; the env detection only fills in unset
values. To force GitHub-shape output from a GitLab runner (rare —
mostly useful when cross-posting to a mirror), pass
`--platform github` explicitly.

## Suppressions

For v0.7, GitLab suppressions are **manual or job-driven**, not
comment-driven. Two paths:

### Path 1 — CLI

The same `bomdrift baseline add <ID>` command works in any GitLab
job or local shell:

```bash
bomdrift baseline add GHSA-xxxx-yyyy-zzzz
bomdrift baseline add CVE-2026-12345 --path custom/baseline.json
```

Commit `.bomdrift/baseline.json` to your MR branch and the next
`bomdrift:diff` run sees the finding as suppressed. See
[Baseline & suppression](./baseline.md) for match-key semantics and
the worked false-positive example.

### Path 2 — manual GitLab job

Copy [`examples/gitlab-ci/suppress.gitlab-ci.yml`](https://github.com/Metbcy/bomdrift/blob/main/examples/gitlab-ci/suppress.gitlab-ci.yml)
to your project (or merge its job into your main `.gitlab-ci.yml`).
The job is `when: manual` — invisible until a reviewer triggers it
from the MR's pipeline view with a `BOMDRIFT_SUPPRESS_ID` variable.
On trigger it runs `bomdrift baseline add` and pushes the result back
to the MR branch using `BOMDRIFT_PUSH_TOKEN`.

### What's NOT in v0.7 (deferred to v0.8)

In-comment `/bomdrift suppress <ID>` flow on GitLab. GitLab's note
webhook fires on every comment on every MR with no command-prefix
filter, so wiring it safely (rate-limit, fork-MR safety, command
parsing, double-trigger debouncing) is materially harder than on
GitHub. v0.7 ships the manual-job path because it covers the same
user need (one click per accepted finding) without standing up a
webhook handler. v0.8 will track the comment-driven flow under a
follow-up issue once we see real adoption data on the v0.7 manual
path.

## Self-Managed GitLab

The template uses `CI_API_V4_URL` (auto-populated on every job)
instead of hardcoding `gitlab.com/api/v4`, so it works against
Self-Managed instances unchanged. Two things to watch:

- **Outbound reachability.** The job downloads the bomdrift archive
  from GitHub Releases and Syft from the upstream install script. If
  your runners can't reach those, mirror them to your internal Nexus
  / Artifactory and override the `BOMDRIFT_RELEASE_BASE_URL` variable
  shown in the example README.
- **Cosign + Sigstore.** Keyless verification needs OIDC connectivity
  to `oauth2.sigstore.dev`. On air-gapped runners, set
  `BOMDRIFT_VERIFY_SIGNATURES=false` — bomdrift fails loudly rather
  than silently skipping when the env var is absent and cosign isn't
  reachable, so the explicit opt-out is the right escape hatch.

## Troubleshooting

See the [examples README troubleshooting table](https://github.com/Metbcy/bomdrift/tree/main/examples/gitlab-ci#troubleshooting)
for the most common failure modes (token scoping, signature
verification on locked-down runners, push-back-to-protected-branch
permissions).

## What's the same vs. the GitHub Action

| Feature | GitHub Action | GitLab template |
|---|---|---|
| Zero-config flow | ✅ | ✅ |
| Syft auto-install | ✅ | ✅ |
| MR/PR comment upsert | ✅ | ✅ |
| `--summary-only` size fallback | ✅ (65k cap) | n/a (1MB cap is rarely hit) |
| Cosign verification of release archive | ✅ | ✅ |
| Per-service monorepo support | ✅ matrix | ✅ matrix (`parallel` keyword) |
| In-comment suppression | ✅ | v0.8 |
| Manual suppression job | n/a | ✅ |
| `<!-- bomdrift:diff -->` marker | ✅ | ✅ (same shape — cross-platform tooling can grep one shape) |

## Comment-driven suppression (advanced)

> **Trade-off up front.** Comment-driven suppression turns a
> reviewer comment like `/bomdrift suppress GHSA-...` into an
> automatic baseline edit. To wire it up safely you need to operate
> a small public webhook handler. The manual suppression job
> documented above is supported and lower-risk; reach for the
> bridge only when the zero-click UX is worth running a service.

The GitHub flow ships out-of-the-box (`comment-suppress` sub-action
fronted by the existing webhook). GitLab requires a webhook handler
because GitLab's `Note Hook` doesn't include a command-prefix filter.

### Bridge

`examples/gitlab-ci/comment-bridge/` ships a Cloudflare Worker
reference implementation that enforces five security guards:

1. Webhook secret verification (constant-time `X-Gitlab-Token`).
2. Event-type filter (`Note Hook` only).
3. Project-ID allowlist.
4. Commenter access_level >= 30 (Developer+ on the project).
5. MR-context guard (rejects fork-MR comment exfiltration).

When the guards pass, the worker triggers the GitLab pipeline with
`BOMDRIFT_NOTE_BODY` set to the raw comment body. The
`bomdrift:suppress` job in `suppress.gitlab-ci.yml` then runs
`bomdrift baseline add --from-comment "$BOMDRIFT_NOTE_BODY"` to
extract the directive and update `.bomdrift/baseline.json`.

The threat model is documented in
[`examples/gitlab-ci/comment-bridge/README.md`](https://github.com/Metbcy/bomdrift/tree/main/examples/gitlab-ci/comment-bridge#threat-model).
The same logic ports to Vercel / Netlify / AWS Lambda — see
[`vercel-equivalent.md`](https://github.com/Metbcy/bomdrift/blob/main/examples/gitlab-ci/comment-bridge/vercel-equivalent.md).

### Recommended hosting

Cloudflare Workers — the reference. The free tier covers most
webhook traffic. `wrangler tail` makes live debugging easy.
Vercel / Netlify Edge Functions are equally good if your team
already operates on those platforms.
