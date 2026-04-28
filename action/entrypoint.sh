#!/usr/bin/env bash
# bomdrift GitHub Action entrypoint. Not yet functional — released alongside v0.1.0.
set -euo pipefail

echo "::warning::bomdrift v0.1.0 not yet released — this Action is a placeholder."
echo "Inputs received:"
printf '  before-sbom = %s\n' "${BEFORE_SBOM:-}"
printf '  after-sbom  = %s\n' "${AFTER_SBOM:-}"
printf '  format      = %s\n' "${INPUT_FORMAT:-}"
printf '  output      = %s\n' "${OUTPUT_FORMAT:-}"
printf '  fail-on     = %s\n' "${FAIL_ON:-}"

exit 0
