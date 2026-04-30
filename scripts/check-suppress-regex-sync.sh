#!/usr/bin/env bash
# CI guard: ensure the suppress-comment regex stays in sync between the
# canonical bash definition (scripts/parse-suppress-comment.sh) and
# every Cloudflare Worker bridge that has its own copy.
#
# The shell and JS regex flavours are not byte-identical (POSIX uses
# [[:space:]], JS uses \s; JS escapes / inside literals), so we
# normalize both sides into a common shape and compare those.
#
# Run from the repo root:
#   bash scripts/check-suppress-regex-sync.sh
#
# Exit codes:
#   0 — all copies agree with the canonical definition
#   1 — at least one copy disagrees (or could not be extracted)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CANON="$REPO_ROOT/scripts/parse-suppress-comment.sh"

# Normalize a regex string into a canonical comparable form:
#   - [[:space:]]  → \s
#   - \/           → /
#   - drop trailing flags (we compare bodies, not flag sets)
normalize() {
    sed -E \
        -e 's/\[\[:space:\]\]/\\s/g' \
        -e 's/\\\//\//g'
}

# Extract the canonical regex body from the shell file.
canon_raw="$(grep -E "^BOMDRIFT_SUPPRESS_REGEX=" "$CANON" \
    | head -n1 \
    | sed -E "s/^BOMDRIFT_SUPPRESS_REGEX='(.*)'$/\1/")"
if [ -z "$canon_raw" ]; then
    echo "FAIL: could not extract BOMDRIFT_SUPPRESS_REGEX from $CANON" >&2
    exit 1
fi
canon_norm="$(printf '%s' "$canon_raw" | normalize)"

# Files that must carry an in-sync copy of the regex. Each entry is a
# bridge worker.js that re-declares the regex (the JS runtime can't
# source bash). Add new bridge files here as they're introduced.
copies=(
    "examples/gitlab-ci/comment-bridge/worker.js"
    "examples/bitbucket-pipelines/comment-bridge/worker.js"
    "examples/azure-devops/comment-bridge/worker.js"
)

fail=0
for rel in "${copies[@]}"; do
    path="$REPO_ROOT/$rel"
    if [ ! -f "$path" ]; then
        # Not yet introduced (e.g. on older branches). Skip rather than fail.
        echo "skip: $rel (not present)"
        continue
    fi
    # Extract the JS literal body between the leading and trailing /.
    # Tolerates an optional flag suffix like /m or /im.
    raw="$(grep -E "^const BOMDRIFT_SUPPRESS_REGEX[[:space:]]*=" "$path" \
        | head -n1 \
        | sed -E 's|^const BOMDRIFT_SUPPRESS_REGEX[[:space:]]*=[[:space:]]*/(.*)/[a-z]*;[[:space:]]*$|\1|')"
    if [ -z "$raw" ]; then
        echo "FAIL: could not extract BOMDRIFT_SUPPRESS_REGEX from $rel" >&2
        fail=1
        continue
    fi
    norm="$(printf '%s' "$raw" | normalize)"
    if [ "$norm" != "$canon_norm" ]; then
        echo "FAIL: regex in $rel disagrees with canonical $CANON" >&2
        echo "  canonical (normalized): $canon_norm" >&2
        echo "  copy      (normalized): $norm" >&2
        fail=1
    else
        echo "ok:   $rel"
    fi
done

if [ "$fail" -ne 0 ]; then
    echo >&2
    echo "Update the disagreeing bridge to match scripts/parse-suppress-comment.sh, or" >&2
    echo "update the canonical definition and every bridge in lockstep." >&2
    exit 1
fi
echo "all suppress-regex copies agree with canonical definition"
