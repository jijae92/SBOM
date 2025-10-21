#!/usr/bin/env bash
set -euo pipefail

echo "[1/3] 취약 베이스 이미지로 빌드"
cat > Dockerfile <<'DOCK'
FROM python:3.9-slim-bullseye
RUN pip install flask==1.1.2
CMD ["python","-c","print('hello')"]
DOCK
docker build -t demo/sbom:old .

echo "demo/sbom:old" > images.txt
bash scripts/scan_image.sh images.txt grype cyclonedx-json
python -m scanner --collect reports --fail-on MEDIUM --out reports/summary-old.json

echo "[2/3] 개선(베이스/패키지 업그레이드)"
cat > Dockerfile <<'DOCK'
FROM python:3.11-slim-bookworm
RUN pip install flask==2.3.2
CMD ["python","-c","print('hello')"]
DOCK
docker build -t demo/sbom:new .

echo "demo/sbom:new" > images.txt
bash scripts/scan_image.sh images.txt grype cyclonedx-json
python -m scanner --collect reports --fail-on MEDIUM --out reports/summary-new.json

echo "[3/3] 감소율 계산"
python - <<'PY'
import json

with open("reports/summary-old.json", "r", encoding="utf-8") as fh:
    old = json.load(fh)
with open("reports/summary-new.json", "r", encoding="utf-8") as fh:
    new = json.load(fh)

summary_old = old.get("summary", {})
summary_new = new.get("summary", {})

for level in ["critical", "high", "medium", "low"]:
    before = int(summary_old.get(level, 0))
    after = int(summary_new.get(level, 0))
    delta = before - after
    print(f"{level}: {before} -> {after}  ({'+' if delta >= 0 else ''}{delta} 개선)")
PY
