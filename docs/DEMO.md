# SBOM 스캐너 데모 시나리오

## 시나리오 요약
`scripts/demo_vuln_image.sh`는 취약 이미지(`demo/sbom:old`)를 빌드해 기준선을 생성하고, 개선된 이미지(`demo/sbom:new`)로 재빌드한 뒤, 요약 보고서의 취약점 감소율을 계산합니다.

## 실행 로그 예시
```bash
$ bash scripts/demo_vuln_image.sh
[1/3] 취약 베이스 이미지로 빌드
...
python -m scanner --collect reports --fail-on MEDIUM --out reports/summary-old.json
[2/3] 개선(베이스/패키지 업그레이드)
...
python -m scanner --collect reports --fail-on MEDIUM --out reports/summary-new.json
[3/3] 감소율 계산
critical: 1 -> 0  (+1 개선)
high: 5 -> 2  (+3 개선)
medium: 8 -> 3  (+5 개선)
low: 12 -> 6  (+6 개선)
```

## 보고서 미리보기
- `reports/summary-old.json` 하이라이트:
  ```json
  {
    "total": 26,
    "critical": 1,
    "top_cves": [
      {"name": "CVE-2020-26116", "count": 3, "severity": "CRITICAL"}
    ]
  }
  ```
- `reports/summary-new.json` 상위 CVE 목록:
  ```json
  {
    "top_cves": [
      {"name": "CVE-2023-4863", "count": 2, "severity": "HIGH"},
      {"name": "CVE-2021-22946", "count": 1, "severity": "MEDIUM"}
    ]
  }
  ```

## End-to-End 파이프라인 데모
1. CodeBuild 프로젝트 실행 → Syft/Grype/Trivy 단계가 SBOM·취약점 리포트를 생성.
2. 산출물은 `s3://<REPORTS_BUCKET>/<OUTPUT_PREFIX>/...` 경로에 업로드.
3. S3 PUT 이벤트 → EventBridge → Lambda 노티파이어가 SNS/Slack 채널로 알림을 발송 (예: “`demo/sbom:new` 스캔 결과 HIGH 2건”).
4. 팀은 Slack 메시지 또는 CloudWatch Logs에서 세부 내역을 확인하고, 보고서 링크(S3 presigned URL)를 통해 HTML/SARIF 결과를 검토합니다.
