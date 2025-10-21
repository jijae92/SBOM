#!/usr/bin/env bash
set -euo pipefail
SYFT_VERSION="v1.16.0"
GRYPE_VERSION="v0.75.0"
TRIVY_VERSION="v0.52.0"
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin ${SYFT_VERSION}
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin ${GRYPE_VERSION}
curl -sSfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin ${TRIVY_VERSION}
syft version && grype version && trivy --version || true
