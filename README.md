# SBOM Vulnerability Monitoring Starter

This repository bootstraps a mono-repo for SBOM-driven vulnerability visibility. It includes:
- A Python 3.11 CLI (`scanner/`) that fabricates SBOMs, merges findings from Grype/Trivy stubs, applies ignore policies, prioritises issues, and writes JSON/Markdown/HTML summaries.
- Infrastructure scaffolding (`infra/`, `lambda/`, `pipeline/`) for an AWS CodeBuild → S3 → Lambda notification pipeline.
- Scripts and documentation for local demos, including before/after container scans.
- Configuration placeholders (`config/`) for Syft options and exception policies with expiry.

Run `pip install -r requirements.txt` followed by `pytest` to validate the baseline. Invoke `python -m scanner.cli demo-app:latest` to generate reports under `reports/`.
