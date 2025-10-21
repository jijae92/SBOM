#!/usr/bin/env bash
set -euo pipefail
LIST_FILE="${1:-images.txt}"
SCANNER="${2:-grype}"
FORMAT="${3:-cyclonedx-json}"
mkdir -p reports/sbom reports/vuln
while IFS= read -r IMG; do
  [ -z "$IMG" ] && continue
  SAFE=$(echo "$IMG" | tr '/:@' '___')
  syft "$IMG" -o "${FORMAT}" > "reports/sbom/${SAFE}.sbom.json"
  if [ "$SCANNER" = "grype" ]; then
    grype sbom:"reports/sbom/${SAFE}.sbom.json" -o json > "reports/vuln/${SAFE}.vuln.json" || true
  else
    trivy image --ignore-unfixed --scanners vuln --format json --output "reports/vuln/${SAFE}.vuln.json" "$IMG" || true
  fi
done < "${LIST_FILE}"
