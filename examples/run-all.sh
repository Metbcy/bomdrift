#!/usr/bin/env bash
# Walk every example scenario, regenerate the rendered output via the
# release binary, and diff it against the pinned `expected-output.md`.
#
# Exit 0 only when every scenario's rendered output matches its pinned
# expectation. The bomdrift binary is invoked in offline mode
# (--no-osv --no-maintainer-age) so the examples stay deterministic.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
BIN="${BOMDRIFT_BIN:-${REPO_ROOT}/target/release/bomdrift}"

if [ ! -x "${BIN}" ]; then
  echo "error: bomdrift binary not found at ${BIN}" >&2
  echo "       run: cargo build --release" >&2
  echo "       or set BOMDRIFT_BIN to your binary path." >&2
  exit 1
fi

# All scenarios that exercise diff (run-all baseline scenario passes
# --baseline; everything else uses the plain offline form).
DIFF_SCENARIOS=(
  axios-incident
  multi-ecosystem
  version-jumps
)

failures=0

# Render via tempfile rather than $(...) command substitution, since bash
# strips trailing newlines from $() output and `bomdrift diff` emits one.
tmpdir="$(mktemp -d)"
trap 'rm -rf "${tmpdir}"' EXIT

for scenario in "${DIFF_SCENARIOS[@]}"; do
  scenario_dir="${SCRIPT_DIR}/${scenario}"
  expected="${scenario_dir}/expected-output.md"
  if [ ! -f "${expected}" ]; then
    echo "skip: ${scenario} has no expected-output.md" >&2
    continue
  fi

  printf '==> %s\n' "${scenario}"
  actual="${tmpdir}/${scenario}.md"
  "${BIN}" diff \
    "${scenario_dir}/before.json" \
    "${scenario_dir}/after.json" \
    --no-osv --no-maintainer-age \
    --output markdown > "${actual}"

  if ! diff -u "${expected}" "${actual}"; then
    echo "FAIL: ${scenario}'s rendered output does not match expected-output.md" >&2
    failures=$((failures + 1))
  else
    echo "ok"
  fi
done

# baseline-suppression takes an extra --baseline arg.
scenario="baseline-suppression"
scenario_dir="${SCRIPT_DIR}/${scenario}"
expected="${scenario_dir}/expected-output.md"
printf '==> %s\n' "${scenario}"
actual="${tmpdir}/${scenario}.md"
"${BIN}" diff \
  "${scenario_dir}/before.json" \
  "${scenario_dir}/after.json" \
  --no-osv --no-maintainer-age \
  --baseline "${scenario_dir}/baseline.json" \
  --output markdown > "${actual}"

if ! diff -u "${expected}" "${actual}"; then
  echo "FAIL: ${scenario}'s rendered output does not match expected-output.md" >&2
  failures=$((failures + 1))
else
  echo "ok"
fi

if [ "${failures}" -gt 0 ]; then
  echo
  echo "${failures} scenario(s) failed." >&2
  exit 1
fi

echo
echo "all examples ok"
