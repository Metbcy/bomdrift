#!/usr/bin/env bash
# Smoke tests for the shared comment-suppress parser.
#
# Run from the repo root:  bash comment-suppress/test.sh
#
# This is intentionally tiny — a handful of asserts that exercise each
# documented return code of parse_bomdrift_suppress. The Rust
# counterpart has its own unit tests in src/baseline.rs; this script
# guards the shell side.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../scripts/parse-suppress-comment.sh
source "$SCRIPT_DIR/../scripts/parse-suppress-comment.sh"

fail_count=0
ok_count=0

assert_parse() {
    local desc="$1" body="$2" expect_rc="$3" expect_id="$4" expect_reason="$5"
    set +e
    parse_bomdrift_suppress "$body"
    local rc=$?
    set -e
    if [ "$rc" != "$expect_rc" ]; then
        echo "FAIL [$desc]: rc=$rc, expected $expect_rc"
        fail_count=$((fail_count + 1))
        return
    fi
    if [ "$BOMDRIFT_PARSED_ID" != "$expect_id" ]; then
        echo "FAIL [$desc]: id='$BOMDRIFT_PARSED_ID', expected '$expect_id'"
        fail_count=$((fail_count + 1))
        return
    fi
    if [ "$BOMDRIFT_PARSED_REASON" != "$expect_reason" ]; then
        echo "FAIL [$desc]: reason='$BOMDRIFT_PARSED_REASON', expected '$expect_reason'"
        fail_count=$((fail_count + 1))
        return
    fi
    ok_count=$((ok_count + 1))
}

assert_parse "id only"            "/bomdrift suppress GHSA-h4j7-mhg8-9q57"               0 "GHSA-h4j7-mhg8-9q57" ""
assert_parse "id + reason"        "/bomdrift suppress CVE-2024-12345 reason: dev only"   0 "CVE-2024-12345"      "dev only"
assert_parse "leading whitespace" "    /bomdrift suppress MAL-2025-1 reason: x"          0 "MAL-2025-1"          "x"
assert_parse "trailing newline"   $'/bomdrift suppress OSV-2024-1\n'                     0 "OSV-2024-1"          ""
assert_parse "multi-line body"    $'thanks!\n/bomdrift suppress GHSA-aaaa-bbbb-cccc reason: ack\n'  0 "GHSA-aaaa-bbbb-cccc" "ack"
assert_parse "no directive"       "looks good to me"                                     1 ""                    ""
assert_parse "bad id prefix"      "/bomdrift suppress NOPE-123"                          2 "NOPE-123"            ""
assert_parse "trailing ws reason" "/bomdrift suppress CVE-2024-1 reason: noisy   "       0 "CVE-2024-1"          "noisy"

echo
echo "passed: $ok_count, failed: $fail_count"
[ "$fail_count" -eq 0 ]
