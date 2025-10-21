# SBOM Vulnerability Scanner 문서

## 소개
- Syft가 컨테이너/이미지에서 CycloneDX 기반 SBOM을 추출합니다.
- Grype 또는 Trivy가 SBOM 구성요소와 매칭하여 취약점(CVE)을 식별하고 점수화합니다.
- 생성된 보고서는 `reports/` 디렉터리에서 검토한 뒤, 파이프라인에서는 S3 버킷에 업로드됩니다.
- Lambda(SNS/Slack 연동)가 새로운 보고서 업로드 이벤트를 구독해 팀에 알림을 전파합니다.

## 빠른 시작
1. 필수 패키지 설치: `make deps`
2. 스캐닝 도구 설치: `bash scripts/install_tools.sh`
3. 스캔 대상 선언: `echo "nginx:1.25-alpine" > images.txt`
4. 실행: `make scan`
5. 결과 확인: `ls reports/` (JSON, SARIF, Markdown, HTML 보고서와 이미지별 SBOM/Vuln 산출물 확인)

## 파이프라인 개요
- AWS CodeBuild `buildspec.yml`은 다음 환경 변수를 통해 동작을 제어합니다.
  - `FAIL_ON`: 임계 심각도(`CRITICAL`, `HIGH` 등)가 발견되면 빌드를 실패로 처리합니다.
  - `REPORTS_BUCKET`: 최종 산출물을 업로드할 S3 버킷 이름.
  - `OUTPUT_PREFIX`: 보고서를 저장할 S3 경로 접두사 (`sbom-reports/<account>/<project>/` 등).
  - `SCANNER`: 사용할 취약점 스캐너 선택(`grype`, `trivy`).
- 파이프라인 순서: CodeCommit/PR → CodeBuild( Syft + {Grype|Trivy} + 리포트 생성 ) → S3 저장 → EventBridge → Lambda 알림.

## 무시 규칙 (.vuln-ignore.yml)
- YAML 형식 예시:
  ```yaml
  rules:
    - ids: [CVE-2024-1234]
      packages: [pkg:pypi/django@4.2.5]
      until: 2025-03-01
      reason: "보안 패치 적용 예정 (분기 배포)"
    - packages: ["openssl"]
      severity: LOW
      until: 2024-12-31
  ```
- `until` 날짜가 경과하면 규칙은 자동으로 비활성화됩니다. 만료 이전에는 로컬/파이프라인 모두에서 동일하게 적용됩니다.
- 조직 공통 규칙은 `config/.vuln-ignore.yml`에 두고, 팀별 예외는 PR로 관리하여 감사를 남깁니다.

## 리포트 산출물
- JSON 요약(`reports/summary.json`):
  ```json
  {
    "total": 4,
    "critical": 1,
    "high": 2,
    "medium": 1,
    "top_packages": [
      {"name": "pkg:pypi/django@4.2.5", "count": 2, "severity": "HIGH"}
    ]
  }
  ```
- SARIF(`reports/summary.sarif`)는 CodeQL, GitHub Advanced Security 등과 통합 가능합니다.
- Markdown(`reports/summary.md`)과 HTML(`reports/summary.html`)은 인트라넷/Slack 공유용 경량 요약을 제공합니다.

## 보안 및 컴플라이언스
- SBOM 생성 및 취약점 스캔은 최근 소프트웨어 공급망 규정(예: EO 14028, NIST SSDF)에 따라 필수입니다.
- 발견된 취약점은 내부 SLA에 맞춰 조치해야 하며, 우선순위는 `scanner/core/prioritizer.py`의 가중치 로직을 따릅니다.
- `.vuln-ignore.yml` 변경, 보고서 업로드, 파이프라인 실행 로그를 버전 관리하여 감사 추적성을 확보합니다.

## 비용 최적화
- S3 버킷에는 라이프사이클 정책을 적용하여 30일 이후 Glacier Deep Archive로 이전하거나 자동 삭제합니다.
- CodeBuild는 캐시(로컬 또는 S3) 기능을 활용해 Syft/Grype 바이너리 다운로드 및 Python 의존성 설치 비용을 절감합니다.
