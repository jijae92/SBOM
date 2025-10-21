#!/usr/bin/env bash
set -euo pipefail

TARGET="${1:-.}"
REPORT_DIR="${REPORT_DIR:-reports}"

echo "Collecting SBOM for repository ${TARGET} (stub)"
python -m scanner.cli "${TARGET}" --report-dir "${REPORT_DIR}" --epss-weight 0.2
