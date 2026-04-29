# GitLab comment-driven suppress bridge

Reference implementation of the webhook handler that turns a
`/bomdrift suppress <ID>` MR comment on GitLab into a manual
pipeline trigger which runs
`bomdrift baseline add --from-comment <body>` on the MR branch.

The bridge is **opt-in advanced infrastructure**. Most teams should
prefer the manual flow in `examples/gitlab-ci/README.md`. Only
deploy this if you've decided the zero-click suppression UX is worth
operating a small public service.

## Architecture

```
┌─────────────────┐    Note Hook     ┌─────────────────────┐
│  GitLab MR note │ ───────────────▶ │ Cloudflare Worker   │
│  /bomdrift …    │   X-Gitlab-Token │ (this directory)    │
└─────────────────┘                  └─────────┬───────────┘
                                               │ verifies 5 guards
                                               ▼
                                     ┌─────────────────────┐
                                     │ GitLab pipeline     │
                                     │ trigger             │
                                     └─────────┬───────────┘
                                               ▼
                                     ┌─────────────────────┐
                                     │ bomdrift baseline   │
                                     │   add --from-comment│
                                     └─────────────────────┘
```

## Threat model

Five guards. Each prevents a distinct class of attack:

| # | Guard | Attack prevented |
|---|---|---|
| 1 | **Webhook secret verification** (`X-Gitlab-Token` constant-time compare) | Unauthenticated POSTs from anyone on the internet. |
| 2 | **Event-type filter** (only `Note Hook`) | Type-confusion: a forged `Push Hook` body that contains a `/bomdrift suppress` line. |
| 3 | **Project-ID allowlist** | Foreign-project replay. |
| 4 | **Commenter-permission check** (`access_level >= 30`, Developer+) | Random outsiders commenting `/bomdrift suppress …` on a public project. |
| 5 | **MR-context guard** (`merge_request.state == "opened"` AND `target_project_id == project.id`) | Fork-MR exfiltration. |

Failures return 4xx without invoking the pipeline trigger. Use
`wrangler tail` for live debugging.

## Deployment

1. `npm install -g wrangler`
2. `wrangler secret put` for `WEBHOOK_SECRET`, `PROJECT_ALLOWLIST`,
   `GITLAB_API_URL`, `BOT_API_TOKEN`, `PIPELINE_TRIGGER_TOKEN`.
3. `wrangler deploy`.
4. In GitLab → Settings → Webhooks: add the Worker URL with
   **Comments** events, SSL verification ON, and the
   `WEBHOOK_SECRET` value.
5. Smoke-test by adding `/bomdrift suppress GHSA-test-1234-aaaa` to
   an MR comment. `wrangler tail` should show the trigger firing.

## curl-based smoke test (no Worker)

The actual `--from-comment` parser is unit-tested in the bomdrift
crate. To smoke-test locally:

```sh
bomdrift baseline add --from-comment "Looks fine. /bomdrift suppress GHSA-mwcw-c2x4-8c55"
# stderr: bomdrift: added 'GHSA-mwcw-c2x4-8c55' to .bomdrift/baseline.json
bomdrift baseline add --from-comment "no directive here"
# exit code: 1
```

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| 401 from worker | `X-Gitlab-Token` mismatch with `WEBHOOK_SECRET`. |
| 403 from worker | Project not allowlisted, or commenter lacks Developer access, or fork-MR. |
| 200 from worker, no pipeline trigger | `PIPELINE_TRIGGER_TOKEN` invalid; `wrangler tail`. |

## Hosting alternatives

See [`vercel-equivalent.md`](./vercel-equivalent.md).
