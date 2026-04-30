# scripts/

Helper scripts shared across the bomdrift platform surface (CI,
shell-bridges, GitHub composite Action). Anything in this directory is
intended to be sourced or invoked from a workflow or documented user
flow — not bundled into the `bomdrift` binary.

## Files

| Script | Purpose |
|---|---|
| `parse-suppress-comment.sh` | Canonical bash library defining the `/bomdrift suppress <ID> [reason: ...]` grammar. Sourced by `comment-suppress/entrypoint.sh`. The Cloudflare Worker bridges (GitLab, Bitbucket, Azure DevOps) each carry an equivalent JS copy of the regex; `check-suppress-regex-sync.sh` keeps them in lockstep. |
| `check-suppress-regex-sync.sh` | CI guard. Extracts the canonical regex from `parse-suppress-comment.sh` and compares (after light POSIX↔JS normalization) against every bridge `worker.js`. Wired into `.github/workflows/ci.yml`. |

## Adding a new bridge

When you add a new SCM bridge worker (e.g. `examples/<scm>/comment-bridge/worker.js`):

1. Copy the regex declaration block from an existing bridge — keep the
   `// CANONICAL DEFINITION lives in scripts/parse-suppress-comment.sh`
   comment intact.
2. Append the new path to the `copies=( ... )` array in
   `check-suppress-regex-sync.sh`.
3. Run `bash scripts/check-suppress-regex-sync.sh` locally; commit only
   when it prints `all suppress-regex copies agree`.
