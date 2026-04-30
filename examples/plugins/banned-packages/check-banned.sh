#!/usr/bin/env bash
# check-banned.sh — bomdrift plugin that flags components whose purl
# matches a prefix in banned.txt. Speaks bomdrift's plugin protocol:
# reads one JSON envelope on stdin, writes one JSON envelope to stdout.
#
# Stdin shape : {"component": {...}, "event": "added"|"version-changed", "before": null|{...}}
# Stdout shape: {"findings": [{"kind", "message", "severity", "rule_id"}, ...]}
#
# Exit non-zero only on internal error; matched bans are normal output.

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
banned_file="${BANNED_PACKAGES_FILE:-$here/banned.txt}"

if ! command -v jq >/dev/null 2>&1; then
  echo "check-banned.sh: jq is required but not on PATH" >&2
  exit 2
fi

input="$(cat)"
purl="$(printf '%s' "$input" | jq -r '.component.purl // empty')"

if [[ -z "$purl" ]]; then
  printf '{"findings":[]}\n'
  exit 0
fi

findings_json='[]'
while IFS= read -r raw_line || [[ -n "$raw_line" ]]; do
  line="${raw_line%%#*}"
  line="${line#"${line%%[![:space:]]*}"}"
  line="${line%"${line##*[![:space:]]}"}"
  [[ -z "$line" ]] && continue

  if [[ "$purl" == "$line"* ]]; then
    sanitized="$(printf '%s' "$line" | tr -c 'A-Za-z0-9' '.' | sed 's/^\.*//; s/\.*$//; s/\.\.*/./g')"
    findings_json="$(jq -c \
      --arg msg "purl $purl matches banned prefix $line" \
      --arg rid "banned-packages.${sanitized}" \
      '. + [{kind:"banned-package", message:$msg, severity:"error", rule_id:$rid}]' \
      <<<"$findings_json")"
  fi
done <"$banned_file"

jq -nc --argjson f "$findings_json" '{findings:$f}'
