#!/usr/bin/env bash
# bomdrift comment-suppress entrypoint.
#
# Triggered by the consumer's workflow on `issue_comment` events. Parses
# `/bomdrift suppress <ID>` from the comment body, runs `bomdrift
# baseline add <ID>`, commits the resulting baseline file to the PR's
# head branch, and reacts to the trigger comment on success or failure.
#
# Non-matching comments (no `/bomdrift suppress` prefix, comments on
# issues rather than PRs, comments by bots) exit 0 without doing
# anything — the consumer wires this onto every issue_comment event
# and we don't want spurious workflow failures.

set -euo pipefail

# Suppress-directive grammar lives in scripts/parse-suppress-comment.sh
# (single source of truth shared with the GitLab/Bitbucket/Azure DevOps
# Cloudflare Worker bridges). CI guard: scripts/check-suppress-regex-sync.sh.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../scripts/parse-suppress-comment.sh
source "$SCRIPT_DIR/../scripts/parse-suppress-comment.sh"

REPO="Metbcy/bomdrift"
GH_DL="https://github.com/${REPO}/releases/download"
# REPO above is the bomdrift project (where the release archives live).
# The consumer's repo (where we POST reactions / read PR data / push the
# baseline commit) comes from GITHUB_REPOSITORY at runtime.
CONSUMER_API_BASE="https://api.github.com/repos/${GITHUB_REPOSITORY:-Metbcy/bomdrift}"
BOMDRIFT_API_BASE="https://api.github.com/repos/${REPO}"

log() {
  printf '::group::bomdrift suppress: %s\n' "$*" >&2
}
endlog() {
  printf '::endgroup::\n' >&2
}
fail() {
  printf '::error::%s\n' "$*" >&2
  exit 1
}
notice() {
  printf '::notice::%s\n' "$*" >&2
}

# ---- Bail-out conditions (non-matching events) -------------------------------

# Only run on issue_comment events targeting a PR (not a plain issue).
event_name="${GITHUB_EVENT_NAME:-}"
if [ "$event_name" != "issue_comment" ]; then
  notice "skipping: GITHUB_EVENT_NAME=$event_name (only issue_comment is supported)"
  exit 0
fi

event_path="${GITHUB_EVENT_PATH:-}"
if [ -z "$event_path" ] || [ ! -f "$event_path" ]; then
  fail "GITHUB_EVENT_PATH not set or missing"
fi

is_pr_comment="$(jq -r '.issue.pull_request != null' "$event_path")"
if [ "$is_pr_comment" != "true" ]; then
  notice "skipping: comment is on an issue, not a pull request"
  exit 0
fi

comment_body="$(jq -r '.comment.body' "$event_path")"
if ! grep -qE '^[[:space:]]*/bomdrift[[:space:]]+suppress[[:space:]]+' <<< "$comment_body"; then
  notice "skipping: comment body does not contain '/bomdrift suppress'"
  exit 0
fi

# Single source of truth: scripts/parse-suppress-comment.sh.
# rc=0 → matched, rc=1 → no directive, rc=2 → matched but malformed ID.
set +e
parse_bomdrift_suppress "$comment_body"
parse_rc=$?
set -e
case "$parse_rc" in
  0) advisory_id="$BOMDRIFT_PARSED_ID"; reason="$BOMDRIFT_PARSED_REASON" ;;
  1) notice "skipping: comment body does not contain a /bomdrift suppress directive"
     exit 0 ;;
  2) fail "advisory id does not match (GHSA|CVE|MAL|OSV)-... shape: ${BOMDRIFT_PARSED_ID}" ;;
  *) fail "internal error: parse_bomdrift_suppress returned $parse_rc" ;;
esac

if [ -z "$advisory_id" ]; then
  fail "could not parse advisory id from comment body: $comment_body"
fi

pr_number="$(jq -r '.issue.number' "$event_path")"
comment_id="$(jq -r '.comment.id' "$event_path")"
commenter="$(jq -r '.comment.user.login' "$event_path")"

# ---- React to acknowledge we're working on it --------------------------------

react() {
  local content="$1"
  local token="${INPUT_GITHUB_TOKEN:-${GITHUB_TOKEN:-}}"
  if [ -z "$token" ]; then return 0; fi
  curl -fsSL -X POST \
    -H "Authorization: Bearer $token" \
    -H "Accept: application/vnd.github+json" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    "${CONSUMER_API_BASE}/issues/comments/${comment_id}/reactions" \
    -d "{\"content\":\"${content}\"}" \
    >/dev/null 2>&1 || true
}

react "eyes"

# ---- Resolve the PR's head ref so we can commit the baseline change ---------

pr_head_ref="$(curl -fsSL \
  -H "Authorization: Bearer ${INPUT_GITHUB_TOKEN:-${GITHUB_TOKEN:-}}" \
  -H "Accept: application/vnd.github+json" \
  "${CONSUMER_API_BASE}/pulls/${pr_number}" \
  | jq -r '.head.ref')"

if [ -z "$pr_head_ref" ] || [ "$pr_head_ref" = "null" ]; then
  react "-1"
  fail "could not resolve PR #${pr_number}'s head ref"
fi

# ---- Download the bomdrift release binary ----------------------------------

resolve_target() {
  case "${RUNNER_OS:-}" in
    Linux)
      case "${RUNNER_ARCH:-}" in
        X64)   printf 'x86_64-unknown-linux-gnu' ;;
        ARM64) printf 'aarch64-unknown-linux-gnu' ;;
        *)     fail "unsupported Linux RUNNER_ARCH: ${RUNNER_ARCH:-<unset>}" ;;
      esac
      ;;
    macOS) printf 'aarch64-apple-darwin' ;;
    Windows) printf 'x86_64-pc-windows-msvc' ;;
    *) fail "unsupported RUNNER_OS: ${RUNNER_OS:-<unset>}" ;;
  esac
}

# Pin to the same major version the consumer is using. Detected from the
# repo's latest release tag — if a v0.5+ binary isn't published yet, this
# whole sub-action is meaningless anyway (the `baseline add` subcommand
# was introduced in v0.5).
resolve_tag() {
  local tag
  tag="$(curl -fsSL -H 'Accept: application/vnd.github+json' \
    "${BOMDRIFT_API_BASE}/releases/latest" \
    | jq -r '.tag_name')"
  if [[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    printf '%s' "$tag"
  else
    fail "could not resolve latest bomdrift release tag (got: '$tag')"
  fi
}

download_bomdrift_binary() {
  local tag="$1"
  local target="$2"
  local stem="bomdrift-${tag}-${target}"
  local archive="${stem}.tar.gz"
  local url="${GH_DL}/${tag}/${archive}"
  local workdir
  workdir="$(mktemp -d)"

  exec 3>&1 1>&2

  log "Downloading ${archive}"
  curl -fSL -o "${workdir}/${archive}" "${url}"
  if [ "${VERIFY_SIGNATURES:-true}" = "true" ]; then
    curl -fSL -o "${workdir}/${archive}.sig" "${url}.sig" || true
    curl -fSL -o "${workdir}/${archive}.pem" "${url}.pem" || true
  fi
  endlog

  if [ "${VERIFY_SIGNATURES:-true}" = "true" ]; then
    if ! command -v cosign >/dev/null 2>&1; then
      fail "cosign not installed but verify-signatures=true"
    fi
    if [ -s "${workdir}/${archive}.sig" ] && [ -s "${workdir}/${archive}.pem" ]; then
      log "Verifying cosign signature for ${archive}"
      cosign verify-blob \
        --certificate-identity "https://github.com/${REPO}/.github/workflows/release.yml@refs/tags/${tag}" \
        --certificate-oidc-issuer https://token.actions.githubusercontent.com \
        --certificate "${workdir}/${archive}.pem" \
        --signature  "${workdir}/${archive}.sig" \
        "${workdir}/${archive}"
      endlog
    else
      fail "cosign signature artifacts missing for ${archive}"
    fi
  fi

  log "Extracting ${archive}"
  tar -C "${workdir}" -xzf "${workdir}/${archive}"
  endlog

  local bin="${workdir}/${stem}/bomdrift"
  if [ ! -x "$bin" ]; then chmod +x "$bin" 2>/dev/null || true; fi

  exec 1>&3 3>&-
  printf '%s' "$bin"
}

# ---- Checkout the PR head, run baseline add, commit + push ----------------

tag="$(resolve_tag)"
target="$(resolve_target)"
bomdrift_bin="$(download_bomdrift_binary "$tag" "$target")"

# Where to do the commit. Use a sibling worktree so we don't pollute the
# runner's checkout (in case the workflow already had `actions/checkout`
# elsewhere).
work_repo="$(mktemp -d)/repo"
log "Cloning ${GITHUB_REPOSITORY}@${pr_head_ref} into ${work_repo}"
git clone --quiet --depth=2 \
  --branch "$pr_head_ref" \
  "https://x-access-token:${INPUT_GITHUB_TOKEN:-${GITHUB_TOKEN:-}}@github.com/${GITHUB_REPOSITORY}.git" \
  "$work_repo"
endlog

cd "$work_repo"
git config user.name "github-actions[bot]"
git config user.email "41898282+github-actions[bot]@users.noreply.github.com"

baseline_path="${BASELINE_PATH:-.bomdrift/baseline.json}"

log "Adding ${advisory_id} to ${baseline_path}"
baseline_args=(baseline add "$advisory_id" --path "$baseline_path")
if [ -n "$reason" ]; then
  baseline_args+=(--reason "$reason")
fi
"$bomdrift_bin" "${baseline_args[@]}"
endlog

# Stage + commit. If `bomdrift baseline add` was a no-op (idempotent
# re-add) the working tree will be clean — exit cleanly with a notice.
git add "$baseline_path"
if git diff --cached --quiet; then
  notice "${advisory_id} already in ${baseline_path}; no commit needed"
  react "+1"
  exit 0
fi

git commit -m "chore(bomdrift): suppress ${advisory_id}

Suppressed via /bomdrift suppress on PR #${pr_number} by @${commenter}.
This advisory ID will be filtered from future bomdrift comments on this
PR (and on any branch that inherits this baseline file)."

log "Pushing baseline change to ${pr_head_ref}"
git push origin "$pr_head_ref"
endlog

react "+1"
notice "suppressed ${advisory_id}; bomdrift will filter it on subsequent runs"
