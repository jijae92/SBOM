

---

# SBOM — **취약 패키지 감시 / 종속성 투명화**

**한 줄 소개**: Syft로 **SBOM 생성** → Grype/Trivy로 **CVE 매칭** → **우선순위 산정/리포트** → CodeBuild가 **S3에 저장** → **S3 이벤트 → Lambda 알림** 파이프라인 데모/스캐폴드. 

---

## 0) 현재 저장소 트리(실측)

아래는 `main` 브랜치 기준, 리포지토리의 최상위 구조입니다(일부 하위 항목은 생략될 수 있음).

```
SBOM/
├─ .github/
│  └─ workflows/           # CI 워크플로우 폴더
├─ config/                 # 스캐너/도구 설정(예: syft 옵션, 예외정책 등)
├─ docs/                   # 문서/데모 자료
├─ infra/                  # 인프라(IaC) 스캐폴드
├─ lambda/                 # S3 이벤트 처리/알림 등 Lambda 코드
├─ pipeline/               # CodeBuild/CodePipeline 등 파이프라인 관련
├─ scanner/                # Python 3.11 CLI 스캐너(보고서 생성 등)
├─ scripts/                # 로컬 스크립트/부트스트랩
├─ tests/                  # pytest
├─ .coverage
├─ .gitignore
├─ .python-version
├─ AGENTS.md
├─ Makefile
├─ Makefile.bak
├─ README.md
├─ requirements.txt
├─ requirements.txt.bak
└─ requirements.txt.bak2
```

> 상기 디렉터리/파일 이름은 GitHub 리포지토리 목록에서 확인됨. 상세 내용/하위 구조는 커밋 진행에 따라 바뀔 수 있습니다. ([GitHub][1])

---

## 1) 소개(Overview)

### 목적 · 문제 정의

* **문제**: 컨테이너/애플리케이션 종속성이 늘어날수록, 어떤 패키지(버전)가 들어갔는지 **투명하게 파악**하기 어렵고, 알려진 취약점(CVE)에 빠르게 대응하기 힘듭니다.
* **목적**: **SBOM(Software Bill of Materials)** 을 표준화된 방식으로 생성하고, **취약점 데이터베이스(CVE)** 와 매칭하여 **우선순위를 부여**하고, **리포트/알림**까지 이어지는 **엔드-투-엔드 가시성**을 제공합니다.

### 핵심 기능(스캐폴드)

* **SBOM 생성**: Syft(이미지/디렉터리 대상) → CycloneDX/SPDX 등 표준 형식
* **취약점 매칭**: Grype/Trivy 결과 통합(중복/스코어 병합)
* **정책·허용목록**: “예외(만료일 포함)” 정책 적용으로 FP 억제
* **리포트**: JSON/Markdown/HTML 콘솔 요약 + 상위 위험 하이라이트
* **파이프라인 데모**: CodeBuild → S3 → (이벤트) Lambda 알림 플로우

> 저장소 설명 요지: “Syft로 SBOM → Grype/Trivy CVE 매칭 → 리포트/우선순위 → CodeBuild가 S3에 저장 → S3 이벤트로 Lambda 알림” ([GitHub][1])

---

## 2) 빠른 시작(Quick Start)

### 요구사항

* **Python 3.11+**
* (선택) **Docker 24+**
* (선택) **AWS CLI v2**, **SAM CLI** (인프라/람다 데모용)
* (선택) **GitHub Actions** 또는 **AWS CodeBuild**

### 설치

```bash
# 1) 클론
git clone https://github.com/jijae92/SBOM.git
cd SBOM

# 2) 가상환경 + 의존성
python3.11 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

### 환경 변수(.env) 예시

> 실제 비밀/토큰은 절대 커밋하지 마세요. `.env.example` → 복사하여 `.env`로 사용하세요.

```env
# .env.example (샘플 값)
SCANNER_FAIL_ON=MEDIUM             # 실패 기준: MEDIUM/HIGH/CRITICAL
SCANNER_INPUT=demo-app:latest      # syft/스캐너 타깃(이미지 or 디렉터리 경로)
REPORT_DIR=reports                 # 결과 저장 경로
ALERT_SNS_TOPIC_ARN=arn:aws:sns:ap-northeast-2:111111111111:sbom-alert
AWS_REGION=ap-northeast-2
```

### 로컬 실행(예시)

```bash
# 스캐너 CLI (예: 컨테이너 이미지 SBOM 생성 + 취약점 매칭 + 보고서 생성)
python -m scanner.cli \
  --input "${SCANNER_INPUT}" \
  --format json \
  --out "${REPORT_DIR}/scan.json"

# 종료코드 규칙(권장):
# - CRITICAL/HIGH ≥ 1 → exit 2
# - MEDIUM ≥ 1        → exit 1
# - LOW/INFO만        → exit 0
echo $?
```

### 테스트

```bash
pytest -q
```

### (옵션) SAM 배포 — 회로/알림 데모

```bash
sam build && sam deploy --guided
# CodeBuild → S3 → (이벤트) Lambda 알림 샘플 스택을 배포해
# S3 업로드 시 알림 흐름까지 체험합니다.
```

---

## 3) 설정/구성(Configuration)

### 주요 설정값

* `SCANNER_FAIL_ON` : 실패 기준(기본 `MEDIUM`) — CI에서 파이프라인 변수로 주입 권장
* `SCANNER_INPUT` : SBOM 대상(컨테이너 이미지 태그 or 로컬 디렉터리)
* `REPORT_DIR` : 결과물 저장 디렉터리
* `ALERT_SNS_TOPIC_ARN` / `AWS_REGION` : 알림 채널/리전

### 도구별 설정 힌트

* **Syft**: 출력 포맷(CycloneDX/SPDX), 제외 경로, 이미지/디렉터리 입력
* **Grype/Trivy**: DB 업데이트 빈도, 취약점 심각도 기준, 무시 목록(만료일 포함)
* **허용목록 파일**: `.sbom-allow.json` (예: 특정 패키지/버전을 임시 허용 + 만료일/사유 필수)

---

## 4) 아키텍처 개요(Architecture)

<img width="1886" height="78" alt="image" src="https://github.com/user-attachments/assets/e76a2593-5baf-48fa-84c8-8fe040ddd467" />


**의존 서비스**

* Syft/Grype/Trivy(로컬 또는 CI 환경)
* AWS: **CodeBuild**, **S3**, **Lambda**, **SNS** (데모 파이프라인) ([GitHub][1])

---

## 5) 운영 방법(Runbook)

### 로그/아티팩트

* **로컬**: `${REPORT_DIR}/scan.json`, 콘솔 요약
* **CI(CodeBuild)**: CloudWatch Logs(`/codebuild/*`), S3 리포트 버킷
* **알림 Lambda**: `/aws/lambda/sbom-notifier-*` 로그 그룹

### 헬스체크/모니터링

* CloudWatch Alarms: CRITICAL/HIGH 발생 카운트, 알림 실패 횟수
* (선택) SNS 구독 이메일/Slack Webhook

### 자주 나는 장애 & 복구 요약

* **히스토리/대용량 스캔 지연**: 불필요 디렉터리 제외, DB 캐시 재활용
  **복구 한 줄**: “대상 축소(폴더/경로 제외) → 도구 DB 업데이트 → 재실행”
* **오탐**: `.sbom-allow.json`에 **사유/만료일**로 예외 등록 → 재스캔
* **알림 실패(KMS/SNS 권한)**: Lambda 역할에 필요한 권한 보강 → 재시도

---

## 6) 보안 · 컴플라이언스(Security & Compliance)

### 비밀 관리

* **절대 비밀값을 리포지토리에 커밋하지 않음** — 예시는 **더미 값** + `.env.example` 만.
* 운영 시크릿은 **AWS Secrets Manager / SSM Parameter Store** 로 관리하며, **KMS CMK** 로 암호화.

### 최소권한(IAM)

* **CI 역할**: S3(리포트 버킷 RW), CloudWatch Logs, (옵션) SNS:Publish
* **알림 Lambda 역할**: SNS:Publish, S3:GetObject(필요 시), CloudWatch Logs
* **원칙**: 파이프라인/람다 역할은 **필요 최소 범위**의 리소스/액션으로 제한

### 데이터 분류/보존

* 리포트에는 **패키지/버전·취약점 정보**가 포함되므로, 취급등급은 조직 정책을 따르고 **보존 90일/폐기** 등 내부 표준에 맞춥니다.

### 신고(보안 이슈)

* 취약점·보안 관련 제보는 공개 이슈가 아닌 **보안 전용 채널**(예: security@예시)로 받고, **재현 시 실제 키 사용 금지**.

---

## 7) 기여 가이드(Contributing)

### 브랜치 전략

* `main`(보호) / `feat/*` / `fix/*` / `chore/*`

### 커밋 규칙

* Conventional Commits: `feat:`, `fix:`, `docs:`, `test:`, `chore:`…

### 코드 스타일

* Python: `ruff`/`black`
* IaC: `cfn-lint`, `sam validate`

### PR 규칙

* PR 템플릿: 변경 요약/리스크/테스트 결과(스크린샷)/체크리스트(시크릿 유출 X)
* **테스트 기준**: 단위테스트 필수, **기본 커버리지 80%+** 유지
* 실패 기준: **CRITICAL/HIGH** 미해결 시 **머지 불가**

---

## 8) 자동화(권장 Make 타깃)

프로젝트에 다음과 같은 타깃을 두면 팀 온보딩이 빠릅니다.

```Makefile
.PHONY: venv install test scan ci
venv:
	python3.11 -m venv .venv && . .venv/bin/activate && pip install -U pip

install:
	. .venv/bin/activate && pip install -r requirements.txt

test:
	. .venv/bin/activate && pytest -q

scan:
	. .venv/bin/activate && python -m scanner.cli \
	  --input "$${SCANNER_INPUT:-demo-app:latest}" \
	  --format json --out "$${REPORT_DIR:-reports}/scan.json"

ci: install test scan
```

---

## 9) 운영 환경별 차이(dev/stage/prod)

* **dev**: 빠른 피드백(경량 스캔), 허용목록 폭넓게, 알림은 Slack 샌드박스
* **stage**: 프로덕션 유사 스캔, 예외 엄격 관리(만료일 필수)
* **prod**: **MEDIUM 이상 실패** 시 배포 차단, 리포트 장기 보존 금지, 알림·대응 런북 연계

---

## 10) 변경 이력 / 라이선스

* **Releases/CHANGELOG**: 추후 `Releases` 탭 또는 `CHANGELOG.md`에 연결(현시점 미공개) ([GitHub][1])
* **License**: 프로젝트 성격에 맞는 라이선스를 `LICENSE` 파일로 명시(예: Apache-2.0/MIT 등 조직 표준)

---

## 11) 부록 — 체크리스트(요약)

* [ ] `.env`만 사용, **실제 시크릿은 절대 커밋 금지**
* [ ] CI에서 **SCANNER_FAIL_ON=MEDIUM/HIGH/CRITICAL** 정책화
* [ ] Lambda/SNS/S3/Logs **최소권한** 점검
* [ ] `.sbom-allow.json` **사유/만료일/승인자** 필수
* [ ] 대용량/히스토리 스캔은 **범위 제한** 및 **캐시/DB 업데이트** 확인

---

