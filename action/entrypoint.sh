#!/usr/bin/env bash
# bomdrift GitHub Action entrypoint.
#
# Resolves the bomdrift release matching this Action's commit (or `latest` when
# the Action is invoked at @main / a branch ref), downloads the archive for the
# runner's OS+arch, optionally cosign-verifies it, runs `bomdrift diff`, and
# upserts the rendered output as a PR comment when invoked from a pull_request
# event.
#
# Inputs are passed via env vars by action.yml's composite step.

set -euo pipefail

REPO="Metbcy/bomdrift"
GH_API="https://api.github.com/repos/${REPO}"
GH_DL="https://github.com/${REPO}/releases/download"

log() {
  printf '::group::bomdrift: %s\n' "$*"
}
endlog() {
  printf '::endgroup::\n'
}
fail() {
  printf '::error::%s\n' "$*" >&2
  exit 1
}

# ---- Resolve the release tag to download ------------------------------------
#
# Action consumers typically pin to a tag (`Metbcy/bomdrift@v1`) or a SHA.
# `${GITHUB_ACTION_REF}` is set by the runner to the ref the consumer pinned
# to. If it's a SemVer tag we use it directly; otherwise we fall back to the
# repo's "latest" release.

resolve_tag() {
  local ref="${GITHUB_ACTION_REF:-}"
  if [[ "$ref" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    printf '%s' "$ref"
    return
  fi
  if [[ "$ref" =~ ^v[0-9]+$ ]]; then
    # Major-version pin (v1). Resolve to the latest release within that
    # major. The mutable v<major> tag is push-forced by the maintainer to
    # the latest matching release; reading "latest" gives the same answer
    # without requiring an extra API call against the tag itself.
    local latest
    latest="$(curl -fsSL -H 'Accept: application/vnd.github+json' \
      "${GH_API}/releases/latest" | grep -m1 '"tag_name"' | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')"
    if [ -z "$latest" ]; then
      fail "could not resolve latest release for ${REPO}"
    fi
    printf '%s' "$latest"
    return
  fi
  # Branch / SHA pin. Use latest release.
  local latest
  latest="$(curl -fsSL -H 'Accept: application/vnd.github+json' \
    "${GH_API}/releases/latest" | grep -m1 '"tag_name"' | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')"
  if [ -z "$latest" ]; then
    fail "could not resolve latest release for ${REPO}"
  fi
  printf '%s' "$latest"
}

# ---- Resolve the runner's target triple --------------------------------------

resolve_target() {
  case "${RUNNER_OS:-}" in
    Linux)
      case "${RUNNER_ARCH:-}" in
        X64) printf 'x86_64-unknown-linux-gnu' ;;
        *)   fail "unsupported Linux RUNNER_ARCH: ${RUNNER_ARCH:-<unset>} (only X64 ships in v0.1.0)" ;;
      esac
      ;;
    macOS)
      case "${RUNNER_ARCH:-}" in
        ARM64) printf 'aarch64-apple-darwin' ;;
        *)     fail "unsupported macOS RUNNER_ARCH: ${RUNNER_ARCH:-<unset>} (only ARM64 ships in v0.1.0)" ;;
      esac
      ;;
    Windows)
      case "${RUNNER_ARCH:-}" in
        X64) printf 'x86_64-pc-windows-msvc' ;;
        *)   fail "unsupported Windows RUNNER_ARCH: ${RUNNER_ARCH:-<unset>} (only X64 ships in v0.1.0)" ;;
      esac
      ;;
    *)
      fail "unsupported RUNNER_OS: ${RUNNER_OS:-<unset>}"
      ;;
  esac
}

# ---- Download + (optionally) verify the bomdrift binary ----------------------

download_bomdrift() {
  local tag="$1"
  local target="$2"
  local ext="tar.gz"
  if [[ "$target" == *windows* ]]; then
    ext="zip"
  fi
  local stem="bomdrift-${tag}-${target}"
  local archive="${stem}.${ext}"
  local url="${GH_DL}/${tag}/${archive}"
  local workdir
  workdir="$(mktemp -d)"

  log "Downloading ${archive}"
  curl -fSL -o "${workdir}/${archive}" "${url}"
  curl -fSL -o "${workdir}/${archive}.sig"  "${url}.sig"  || true
  curl -fSL -o "${workdir}/${archive}.pem"  "${url}.pem"  || true
  endlog

  if command -v cosign >/dev/null 2>&1; then
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
      printf '::warning::cosign signature artifacts missing for %s; skipping verification\n' "${archive}"
    fi
  else
    printf '::warning::cosign not installed on this runner; skipping signature verification\n'
  fi

  log "Extracting ${archive}"
  if [[ "$ext" == "zip" ]]; then
    7z x -o"${workdir}" "${workdir}/${archive}" >/dev/null
  else
    tar -C "${workdir}" -xzf "${workdir}/${archive}"
  fi
  endlog

  local bin="${workdir}/${stem}/bomdrift"
  if [[ "$target" == *windows* ]]; then
    bin="${bin}.exe"
  fi
  if [ ! -x "$bin" ]; then
    chmod +x "$bin" 2>/dev/null || true
  fi
  printf '%s' "$bin"
}

# ---- Run bomdrift diff -------------------------------------------------------

run_diff() {
  local bin="$1"
  local before="$2"
  local after="$3"
  local fmt="${4:-markdown}"
  local input_format="${5:-auto}"

  local args=(diff "$before" "$after" --output "$fmt")
  if [ "$input_format" != "auto" ]; then
    args+=(--format "$input_format")
  fi

  log "Running bomdrift ${args[*]}"
  "$bin" "${args[@]}"
  endlog
}

# ---- main --------------------------------------------------------------------

main() {
  local before="${BEFORE_SBOM:-}"
  local after="${AFTER_SBOM:-}"
  local input_format="${INPUT_FORMAT:-auto}"
  local output_format="${OUTPUT_FORMAT:-markdown}"
  local comment_on_pr="${COMMENT_ON_PR:-true}"
  local fail_on="${FAIL_ON:-none}"

  if [ -z "$before" ] || [ -z "$after" ]; then
    fail "before-sbom and after-sbom inputs are required"
  fi
  if [ ! -f "$before" ]; then
    fail "before-sbom not found: $before"
  fi
  if [ ! -f "$after" ]; then
    fail "after-sbom not found: $after"
  fi

  if [ "$fail_on" != "none" ]; then
    printf '::warning::fail-on=%s requested but not yet implemented in v0.1.0; treating as none\n' "$fail_on"
  fi

  local tag target bin out
  tag="$(resolve_tag)"
  target="$(resolve_target)"
  printf 'bomdrift Action: tag=%s target=%s\n' "$tag" "$target"

  bin="$(download_bomdrift "$tag" "$target")"

  out="$(run_diff "$bin" "$before" "$after" "$output_format" "$input_format")"
  printf '%s\n' "$out"

  # Always also write to the step summary so users see the diff even when no
  # PR comment is posted.
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ] && [ "$output_format" = "markdown" ]; then
    printf '%s\n' "$out" >> "$GITHUB_STEP_SUMMARY"
  fi

  if [ "$comment_on_pr" = "true" ] \
     && [ "${GITHUB_EVENT_NAME:-}" = "pull_request" ] \
     && [ "$output_format" = "markdown" ]; then
    post_pr_comment "$out"
  fi
}

# ---- PR comment upsert -------------------------------------------------------
#
# Find an existing comment whose body starts with `<!-- bomdrift:diff -->`
# (our marker); patch it if found, create a new one otherwise. Keeps the diff
# in a single comment that updates on every PR push, instead of accumulating.

post_pr_comment() {
  local body="$1"
  local marker='<!-- bomdrift:diff -->'
  local payload
  body="${marker}
${body}"

  local pr_number
  pr_number="$(jq -r '.pull_request.number // .number // empty' "${GITHUB_EVENT_PATH:-/dev/null}")"
  if [ -z "$pr_number" ]; then
    printf '::warning::could not resolve PR number from event payload; skipping comment\n'
    return
  fi

  local token="${GITHUB_TOKEN:-${INPUT_GITHUB_TOKEN:-}}"
  if [ -z "$token" ]; then
    printf '::warning::no GITHUB_TOKEN available; skipping PR comment\n'
    return
  fi

  local comments_url="${GITHUB_API_URL:-https://api.github.com}/repos/${GITHUB_REPOSITORY}/issues/${pr_number}/comments"

  log "Looking for existing bomdrift comment on PR #${pr_number}"
  local existing_id
  existing_id="$(curl -fsSL \
    -H "Authorization: Bearer ${token}" \
    -H 'Accept: application/vnd.github+json' \
    "${comments_url}?per_page=100" \
    | jq -r --arg marker "$marker" \
        '[.[] | select(.body | startswith($marker))] | first | .id // empty')"
  endlog

  payload="$(jq -nc --arg b "$body" '{body: $b}')"

  if [ -n "$existing_id" ]; then
    log "Updating bomdrift comment ${existing_id}"
    curl -fsSL -X PATCH \
      -H "Authorization: Bearer ${token}" \
      -H 'Accept: application/vnd.github+json' \
      -H 'Content-Type: application/json' \
      -d "$payload" \
      "${GITHUB_API_URL:-https://api.github.com}/repos/${GITHUB_REPOSITORY}/issues/comments/${existing_id}" \
      > /dev/null
  else
    log "Creating new bomdrift comment on PR #${pr_number}"
    curl -fsSL -X POST \
      -H "Authorization: Bearer ${token}" \
      -H 'Accept: application/vnd.github+json' \
      -H 'Content-Type: application/json' \
      -d "$payload" \
      "${comments_url}" \
      > /dev/null
  fi
  endlog
}

main "$@"
