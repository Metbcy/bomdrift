# Bitbucket Cloud comment-driven suppress bridge

Reference implementation of a webhook handler that turns a
`/bomdrift suppress <ID>` PR comment on Bitbucket Cloud into a
custom-pipeline trigger which runs
`bomdrift baseline add --from-comment <body>` on the PR's source
branch.

The bridge is **opt-in advanced infrastructure**. Most teams should
prefer the manual flow in `examples/bitbucket-pipelines/README.md`
(commit `.bomdrift/baseline.json` directly). Only deploy this if
you've decided the zero-click suppression UX is worth operating a
small public service.

## Architecture

```
┌─────────────────────────┐  pullrequest:comment_created  ┌─────────────────────┐
│  Bitbucket PR comment   │ ──────────────────────────────▶│ Cloudflare Worker   │
│  /bomdrift suppress …   │   X-Hub-Signature (HMAC)       │ (this directory)    │
└─────────────────────────┘                                └─────────┬───────────┘
                                                                     │ 5 guards
                                                                     ▼
                                                           ┌─────────────────────┐
                                                           │ Bitbucket custom    │
                                                           │ pipeline trigger    │
                                                           │ (POST /pipelines/)  │
                                                           └─────────┬───────────┘
                                                                     ▼
                                                           ┌─────────────────────┐
                                                           │ bomdrift baseline   │
                                                           │  add --from-comment │
                                                           └─────────────────────┘
```

## Threat model

Five guards. Each prevents a distinct class of attack:

| # | Guard | Attack prevented |
|---|---|---|
| 1 | **Webhook HMAC** (`X-Hub-Signature: sha256=<hex>`, constant-time HMAC-SHA256 compare against the **byte-exact** request body) | Unauthenticated POSTs from anyone on the internet; replay with a tampered body. |
| 2 | **Event-type filter** (`X-Event-Key === "pullrequest:comment_created"`) | Type-confusion: a forged `pullrequest:approved` body that contains a `/bomdrift suppress` line. |
| 3 | **Repo allowlist** (`REPO_ALLOWLIST="org/repo,org/other"` matched against `repository.full_name`) | Foreign-repo replay using a leaked secret. |
| 4 | **Commenter-permission lookup** (`/2.0/workspaces/<ws>/permissions?q=user.account_id="<id>"` → `permission ∈ {write, admin, owner}`) | Random outsiders commenting `/bomdrift suppress …` on a public repo. |
| 5 | **PR-context guard** (`pullrequest.state === "OPEN"` AND `source.repository.full_name === destination.repository.full_name`) | Fork-PR exfiltration: contributors with a fork-PR open could otherwise suppress findings on the upstream baseline. |

Failures return 4xx without invoking the pipeline trigger. Use
`wrangler tail` for live debugging.

## Deployment

1. `npm install -g wrangler`
2. `wrangler secret put` for each of:
   - `WEBHOOK_SECRET` — the secret you'll configure in the Bitbucket
     webhook UI.
   - `REPO_ALLOWLIST` — comma-separated `org/repo` list.
   - `BITBUCKET_API_TOKEN` — App Password for the bot user, scopes
     `pullrequest:write` + `repository:read` + `pipeline:write`.
   - `BITBUCKET_TRIGGER_USER` (optional) — the bot's `account_id`,
     used only for logging.
   - `SUPPRESS_PIPELINE_REF` (optional) — branch to run the custom
     pipeline on. Defaults to the PR source branch.
3. `wrangler deploy`.
4. Add the custom pipeline definition to `bitbucket-pipelines.yml`
   (see the `bomdrift-comment-suppress` step in
   [`../bitbucket-pipelines.yml`](../bitbucket-pipelines.yml)).
5. In Bitbucket → Repository settings → Webhooks: add the Worker URL
   with **Pull request → Comment created** event, the
   `WEBHOOK_SECRET` filled in, and SSL verification on.
6. Smoke-test by commenting `/bomdrift suppress GHSA-test-1234-aaaa`
   on an open PR. `wrangler tail` should show the guards passing
   and the trigger firing.

## Bitbucket gotchas

- **The signed body is the raw bytes**, not the parsed JSON. The
  Worker therefore reads `request.arrayBuffer()` first and only
  parses JSON after the HMAC check passes. Don't refactor that.
- **Bitbucket allows both `account_id` and `uuid` for actors** in
  the webhook payload depending on workspace privacy settings. The
  Worker tries both, in that order.
- **Custom pipelines must be pre-declared** in
  `bitbucket-pipelines.yml` (under `definitions:` and referenced
  by name in `pipelines: custom:`). The Worker triggers by name —
  if the step doesn't exist, the API call returns 400.
- **Permission API quirk:** `permissions` returns owner / admin /
  collaborator / contributor — but the API surfaces these as the
  string set `{"owner","admin","write","read"}`. The Worker accepts
  `write`, `admin`, and `owner`; `read` is explicitly rejected.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| 401 from worker | `X-Hub-Signature` mismatch with `WEBHOOK_SECRET`. Bitbucket's UI silently truncates trailing whitespace in the secret field — re-paste cleanly. |
| 403 from worker | Repo not allowlisted, commenter lacks `write` access, or fork-PR. |
| 502 from worker | Pipeline trigger 4xx — usually means the `bomdrift-comment-suppress` custom step isn't defined in the target branch's `bitbucket-pipelines.yml`. |
| Worker silently 204s | Comment didn't match the `BOMDRIFT_SUPPRESS_REGEX`. Check the canonical regex in [`../../../scripts/parse-suppress-comment.sh`](../../../scripts/parse-suppress-comment.sh). |

## Hosting alternatives

See [`vercel-equivalent.md`](./vercel-equivalent.md).
