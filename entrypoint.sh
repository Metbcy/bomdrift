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
  # Write workflow-command directives to stderr, not stdout. log/endlog are
  # called from inside helper functions whose stdout is captured by callers
  # (`bin="$(download_bomdrift ...)"` and `run_diff ... | tee out_file`).
  # Writing to stdout would inject `::group::...` directives into the
  # captured value or the PR comment body. GitHub Actions parses workflow
  # commands from BOTH streams, so directing to stderr preserves the
  # job-log UI grouping while keeping the stdout streams clean for the
  # data they're carrying.
  printf '::group::bomdrift: %s\n' "$*" >&2
}
endlog() {
  printf '::endgroup::\n' >&2
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
        X64)   printf 'x86_64-unknown-linux-gnu' ;;
        ARM64) printf 'aarch64-unknown-linux-gnu' ;;
        *)     fail "unsupported Linux RUNNER_ARCH: ${RUNNER_ARCH:-<unset>} (supported: X64, ARM64)" ;;
      esac
      ;;
    macOS)
      case "${RUNNER_ARCH:-}" in
        ARM64) printf 'aarch64-apple-darwin' ;;
        *)     fail "unsupported macOS RUNNER_ARCH: ${RUNNER_ARCH:-<unset>} (only ARM64 ships)" ;;
      esac
      ;;
    Windows)
      case "${RUNNER_ARCH:-}" in
        X64) printf 'x86_64-pc-windows-msvc' ;;
        *)   fail "unsupported Windows RUNNER_ARCH: ${RUNNER_ARCH:-<unset>} (only X64 ships)" ;;
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
  local verify="${VERIFY_SIGNATURES:-true}"
  local ext="tar.gz"
  if [[ "$target" == *windows* ]]; then
    ext="zip"
  fi
  local stem="bomdrift-${tag}-${target}"
  local archive="${stem}.${ext}"
  local url="${GH_DL}/${tag}/${archive}"
  local workdir
  workdir="$(mktemp -d)"

  # The caller captures this function's stdout (`bin="$(download_bomdrift
  # ...)"`) to receive the bomdrift-binary path. Anything that leaks onto
  # stdout from the work below — log/endlog directives, cosign's
  # "Verified OK", curl progress in some terminal modes, tar output — would
  # contaminate $bin. Redirect the whole work region to stderr via fd 3 →
  # 1, then restore stdout just before the final printf that emits the
  # bin path.
  exec 3>&1 1>&2

  log "Downloading ${archive}"
  curl -fSL -o "${workdir}/${archive}" "${url}"
  if [ "$verify" = "true" ]; then
    curl -fSL -o "${workdir}/${archive}.sig"  "${url}.sig"  || true
    curl -fSL -o "${workdir}/${archive}.pem"  "${url}.pem"  || true
  fi
  endlog

  if [ "$verify" = "true" ]; then
    if ! command -v cosign >/dev/null 2>&1; then
      # `verify-signatures: true` is the default and contracts-with the
      # consumer that we WILL verify. If cosign is missing, fail loudly
      # rather than silently degrading — that's the whole point of the
      # opt-out flag (consumers who deliberately want no verification
      # set verify-signatures: false).
      fail "cosign not installed but verify-signatures=true. Install cosign in a prior step or set verify-signatures: false."
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
      fail "cosign signature artifacts missing for ${archive} but verify-signatures=true. The release may have been tampered with, or this tag predates cosign signing."
    fi
  else
    printf '::notice::verify-signatures=false; skipping cosign verification of %s\n' "${archive}"
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

  # Restore stdout and emit the bin path as the function's "return value".
  exec 1>&3 3>&-
  printf '%s' "$bin"
}

# ---- Generate an SBOM for one side of the diff -------------------------------
#
# Used in the v0.5 zero-config flow when the consumer didn't supply a
# pre-computed `before-sbom` / `after-sbom`. The action's composite step
# already checked out the requested ref into `${checkout_dir}` and installed
# Syft into PATH; this function just runs the scan.
#
# Args:
#   $1 — checkout directory (absolute path, e.g. ${GITHUB_WORKSPACE}/__bomdrift_after)
#   $2 — project subdirectory within the checkout (default ".")
#   $3 — output SBOM path (CycloneDX JSON)

generate_sbom() {
  local checkout_dir="$1"
  local subpath="${2:-.}"
  local out="$3"

  if [ ! -d "$checkout_dir" ]; then
    fail "checkout directory missing: ${checkout_dir} (the in-action checkout step likely failed; check the job log for actions/checkout errors)"
  fi
  # Trim a trailing slash, then trim leading "./" so users who write `path: ./`
  # or `path: services/api/` get the canonical path Syft expects.
  local clean="${subpath%/}"
  clean="${clean#./}"
  if [ -z "$clean" ]; then
    clean="."
  fi
  local source_dir="${checkout_dir}/${clean}"
  if [ ! -d "$source_dir" ]; then
    # Build an actionable error: what we tried, what's actually on disk
    # at that level, and where to read about the monorepo pattern. The
    # most common cause of this firing is a `path:` typo or a `path:`
    # value that exists in `after-ref` but not `before-ref` (a directory
    # added in the PR head). Show the first ~10 entries at the checkout
    # root so the reviewer can see whether the directory is just
    # misnamed (e.g. `services/api` vs `service/api`).
    local actual
    actual="$(cd "$checkout_dir" && ls -1 2>/dev/null | head -10 | sed 's/^/    /')"
    if [ -z "$actual" ]; then
      actual="    (checkout root is empty)"
    fi
    fail "scan path not found: ${source_dir}
  Resolved from input path='${subpath}' against checkout '${checkout_dir}'.
  The checkout root contains:
${actual}

  Common causes:
    - typo in the 'path:' input (case-sensitive; 'Services/api' != 'services/api')
    - the directory exists in after-ref but not before-ref (or vice versa)
    - a monorepo split renamed the directory in the default branch since the PR was opened
  See https://metbcy.github.io/bomdrift/github-action.html#monorepo-setup
  for the matrix-per-service recipe."
  fi

  if ! command -v syft >/dev/null 2>&1; then
    fail "syft not installed; the action's Syft-install step should have run before this point"
  fi

  log "Generating SBOM for ${source_dir}"
  # `dir:` source pins Syft to directory cataloging (no container or git
  # plumbing). CycloneDX-JSON because bomdrift's CDX parser is the most
  # battle-tested code path; SPDX/Syft-native are also accepted but have
  # less coverage in our real-world corpus.
  syft scan "dir:${source_dir}" -o "cyclonedx-json=${out}" --quiet
  endlog
}

# ---- Run bomdrift diff -------------------------------------------------------

run_diff() {
  local bin="$1"
  local before="$2"
  local after="$3"
  local fmt="${4:-markdown}"
  local input_format="${5:-auto}"
  shift 5
  # Remaining args are passed through verbatim — used for policy flags such as
  # `--config`, `--fail-on`, and diff budgets without re-positioning params.

  local args=(diff "$before" "$after" --output "$fmt")
  if [ "$input_format" != "auto" ]; then
    args+=(--format "$input_format")
  fi
  if [ "$#" -gt 0 ]; then
    args+=("$@")
  fi

  log "Running bomdrift ${args[*]}"
  "$bin" "${args[@]}"
  endlog
}

# ---- main --------------------------------------------------------------------

main() {
  local before="${BEFORE_SBOM:-}"
  local after="${AFTER_SBOM:-}"
  local before_ref="${BEFORE_REF:-}"
  local after_ref="${AFTER_REF:-}"
  local before_checkout="${BEFORE_CHECKOUT_DIR:-}"
  local after_checkout="${AFTER_CHECKOUT_DIR:-}"
  local scan_path="${BOMDRIFT_PATH:-.}"
  local input_format="${INPUT_FORMAT:-auto}"
  local output_format="${OUTPUT_FORMAT:-markdown}"
  local comment_on_pr="${COMMENT_ON_PR:-true}"
  local comment_size_limit="${COMMENT_SIZE_LIMIT:-60000}"
  local config_path="${CONFIG_PATH:-}"
  local findings_only="${FINDINGS_ONLY:-false}"
  local max_added="${MAX_ADDED:-}"
  local max_removed="${MAX_REMOVED:-}"
  local max_version_changed="${MAX_VERSION_CHANGED:-}"
  local fail_on="${FAIL_ON:-none}"
  local baseline="${BASELINE:-}"
  local upload_to_cs="${UPLOAD_TO_CODE_SCANNING:-false}"

  # ---- Resolve "before" SBOM path -------------------------------------------
  #
  # Three modes, in priority order:
  #   1. BEFORE_SBOM is set — explicit-SBOM (v0.4-compat / advanced) flow.
  #      Validate the path exists; never re-generate.
  #   2. BEFORE_SBOM is unset AND a checkout dir exists — zero-config flow.
  #      Generate via Syft into a tempfile.
  #   3. Neither — fail loudly with migration guidance.

  if [ -z "$before" ]; then
    if [ -z "$before_ref" ]; then
      fail "before-ref is empty and before-sbom is unset. On non-pull_request events the default is empty; supply before-ref explicitly OR provide before-sbom."
    fi
    if [ -z "$before_checkout" ] || [ ! -d "$before_checkout" ]; then
      fail "in-action checkout of '${before_ref}' produced no directory at '${before_checkout}'. Check the actions/checkout step in the job log."
    fi
    # GNU and BSD `mktemp` disagree on `--suffix`, and macOS-hosted runners
    # ship the BSD form. A predictable filename under $RUNNER_TEMP (always
    # set on GitHub-hosted runners; falls back to /tmp elsewhere) avoids
    # the portability cliff.
    before="${RUNNER_TEMP:-/tmp}/bomdrift_before.cdx.json"
    generate_sbom "$before_checkout" "$scan_path" "$before"
  fi
  if [ ! -f "$before" ]; then
    fail "before-sbom not found: $before"
  fi

  if [ -z "$after" ]; then
    if [ -z "$after_ref" ]; then
      fail "after-ref is empty and after-sbom is unset. Supply after-ref explicitly OR provide after-sbom."
    fi
    if [ -z "$after_checkout" ] || [ ! -d "$after_checkout" ]; then
      fail "in-action checkout of '${after_ref}' produced no directory at '${after_checkout}'. Check the actions/checkout step in the job log."
    fi
    after="${RUNNER_TEMP:-/tmp}/bomdrift_after.cdx.json"
    generate_sbom "$after_checkout" "$scan_path" "$after"
  fi
  if [ ! -f "$after" ]; then
    fail "after-sbom not found: $after"
  fi
  # Baseline is optional but if specified must exist — typo'd paths
  # silently no-op'ing would defeat the whole point of opting in.
  if [ -n "$baseline" ] && [ ! -f "$baseline" ]; then
    fail "baseline file not found: $baseline"
  fi

  local tag target bin out rc
  tag="$(resolve_tag)"
  target="$(resolve_target)"
  printf 'bomdrift Action: tag=%s target=%s\n' "$tag" "$target"

  bin="$(download_bomdrift "$tag" "$target")"

  # `set -euo pipefail` would abort the script the instant bomdrift exits
  # non-zero (e.g. when --fail-on trips), short-circuiting the PR-comment
  # post that consumers rely on for visibility. The `tee` + PIPESTATUS
  # capture lets us preserve bomdrift's exit code while still posting the
  # comment from the captured body.
  local out_file
  out_file="$(mktemp)"
  local fail_on_args=()
  if [ "$fail_on" != "none" ]; then
    fail_on_args=(--fail-on "$fail_on")
  fi
  local baseline_args=()
  if [ -n "$baseline" ]; then
    baseline_args=(--baseline "$baseline")
  fi
  local config_args=()
  if [ -n "$config_path" ]; then
    config_args=(--config "$config_path")
  fi
  local focus_args=()
  if [ "$findings_only" = "true" ]; then
    focus_args=(--findings-only)
  fi
  local budget_args=()
  if [ -n "$max_added" ]; then
    budget_args+=(--max-added "$max_added")
  fi
  if [ -n "$max_removed" ]; then
    budget_args+=(--max-removed "$max_removed")
  fi
  if [ -n "$max_version_changed" ]; then
    budget_args+=(--max-version-changed "$max_version_changed")
  fi
  # When emitting SARIF, write to a stable workspace path so the
  # codeql-action upload step can pick it up. We always set this when
  # output is sarif (whether or not upload is enabled) — the file is
  # cheap and consumers running their own SARIF upload pipeline benefit
  # too. stdout still receives the SARIF for back-compat callers that
  # piped it to their own file in a follow-up step.
  local sarif_args=()
  local sarif_path=""
  if [ "$output_format" = "sarif" ]; then
    sarif_path="${GITHUB_WORKSPACE:-$PWD}/bomdrift.sarif"
    sarif_args=(--output-file "$sarif_path")
  fi

  set +e
  run_diff "$bin" "$before" "$after" "$output_format" "$input_format" \
    "${config_args[@]}" "${fail_on_args[@]}" "${baseline_args[@]}" \
    "${focus_args[@]}" "${budget_args[@]}" "${sarif_args[@]}" \
    | tee "$out_file"
  rc="${PIPESTATUS[0]}"
  set -e
  out="$(cat "$out_file")"
  rm -f "$out_file"

  # When SARIF was written via --output-file, the file is the canonical
  # output for downstream upload; leave $out (terminal mirror) unused.
  if [ "$output_format" = "sarif" ] && [ -n "$sarif_path" ] && [ -f "$sarif_path" ]; then
    printf 'bomdrift Action: SARIF written to %s\n' "$sarif_path"
  fi
  : "$upload_to_cs"  # consumed by composite step in action.yml; reference here keeps shellcheck quiet

  # Always also write to the step summary so users see the diff even when no
  # PR comment is posted.
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ] && [ "$output_format" = "markdown" ]; then
    printf '%s\n' "$out" >> "$GITHUB_STEP_SUMMARY"
  fi

  if [ "$comment_on_pr" = "true" ] \
     && [ "${GITHUB_EVENT_NAME:-}" = "pull_request" ] \
     && [ "$output_format" = "markdown" ]; then

    local body="$out"
    # Re-render in summary-only mode when the full body would blow past
    # GitHub's comment-size cap. The full markdown is still in the step
    # summary (written above), so the reviewer can click through; the
    # comment stays scannable. `comment_size_limit=0` disables the
    # fallback for users on Enterprise GHE with raised limits.
    local body_len=${#out}
    if [ "$comment_size_limit" -gt 0 ] && [ "$body_len" -gt "$comment_size_limit" ]; then
      printf '::warning::bomdrift output is %d bytes (cap %d); falling back to --summary-only for the PR comment\n' \
        "$body_len" "$comment_size_limit"
      local summary_file
      summary_file="$(mktemp)"
      set +e
      run_diff "$bin" "$before" "$after" "$output_format" "$input_format" \
        "${config_args[@]}" "${fail_on_args[@]}" "${baseline_args[@]}" \
        "${focus_args[@]}" "${budget_args[@]}" --summary-only > "$summary_file"
      set -e
      body="$(cat "$summary_file")"
      rm -f "$summary_file"
    fi

    post_pr_comment "$body"
  fi

  # bomdrift exit 2 means a configured policy gate tripped; surface that to
  # the runner so the workflow step fails as the consumer requested. Other
  # non-zero codes are bomdrift bugs / parse errors and should also propagate.
  exit "$rc"
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
