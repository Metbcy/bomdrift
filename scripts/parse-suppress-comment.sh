#!/usr/bin/env bash
# Single source of truth for the bomdrift suppress-comment grammar.
#
# This file is sourced by:
#   - comment-suppress/entrypoint.sh   (GitHub composite Action shell)
# And is the canonical reference (kept in sync via
# scripts/check-suppress-regex-sync.sh) for:
#   - examples/gitlab-ci/comment-bridge/worker.js
#   - examples/bitbucket-pipelines/comment-bridge/worker.js (v0.9.5+)
#   - examples/azure-devops/comment-bridge/worker.js       (v0.9.5+)
#
# The Rust counterpart `bomdrift::baseline::parse_comment_directive`
# carries a doc comment pointing at this file. Rust regex syntax differs
# from POSIX/JS so the parsers can't literally share bytes; the human-
# readable contract below is what the implementations agree on.
#
# Grammar (one directive per comment, single-line):
#
#   /bomdrift suppress <ID>[ reason: <free-text>]
#
# where <ID> matches  (GHSA|CVE|MAL|OSV)-[A-Za-z0-9-]+
# (real GHSA ids use lowercase a-z; CVE / MAL / OSV are uppercase digits
# with year-id segments — the union grammar accepts both casings.)
#
# Leading whitespace is permitted; trailing whitespace after the reason
# is stripped. The directive may be preceded by other lines in a
# multi-line comment body; this parser scans line-by-line and matches
# the first directive it finds.

# Public regex constants. Exported so wrapping scripts (and the CI
# regex-sync guard) can read them without re-sourcing in a subshell.
# shellcheck disable=SC2034
BOMDRIFT_SUPPRESS_REGEX='^[[:space:]]*/bomdrift[[:space:]]+suppress[[:space:]]+([A-Za-z0-9-]+)([[:space:]]+reason:[[:space:]]*(.+))?[[:space:]]*$'
# shellcheck disable=SC2034
BOMDRIFT_ID_VALIDATE='^(GHSA|CVE|MAL|OSV)-[A-Za-z0-9-]+$'

# parse_bomdrift_suppress <comment-body>
#
# Sets the following variables on success:
#   BOMDRIFT_PARSED_ID      — the advisory ID
#   BOMDRIFT_PARSED_REASON  — the reason text (may be empty)
#
# Returns:
#   0 — directive found and ID is well-formed
#   1 — no directive found (caller should treat as a no-op skip)
#   2 — directive found but ID is malformed (caller should fail loudly)
parse_bomdrift_suppress() {
    local body="$1"
    local line
    BOMDRIFT_PARSED_ID=""
    BOMDRIFT_PARSED_REASON=""

    while IFS= read -r line || [ -n "$line" ]; do
        if [[ "$line" =~ $BOMDRIFT_SUPPRESS_REGEX ]]; then
            local id="${BASH_REMATCH[1]}"
            local reason="${BASH_REMATCH[3]:-}"
            # Trim trailing whitespace from reason.
            reason="${reason%"${reason##*[![:space:]]}"}"
            if [[ ! "$id" =~ $BOMDRIFT_ID_VALIDATE ]]; then
                BOMDRIFT_PARSED_ID="$id"
                return 2
            fi
            BOMDRIFT_PARSED_ID="$id"
            BOMDRIFT_PARSED_REASON="$reason"
            return 0
        fi
    done <<< "$body"

    return 1
}
