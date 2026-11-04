# PR Guard Server

> **DevSecOps AI Security Gatekeeper & Automated PR Code Reviewer**  
> GitHub Pull Request(PR)의 오픈소스 취약점(CVE), 런타임 환경 결함, 시크릿 노출 및 비즈니스 로직 취약점을 정밀 분석하고, GitHub Checks API를 통해 위험 코드의 병합(Merge)을 원천 차단하는 엔터프라이즈 보안 게이트키퍼 솔루션입니다.

---

## 핵심 기능 (Key Features)

1. **자동 보안 스캔 및 Reachability 분석**
   - Aqua Security Trivy 엔진을 통한 취약점(CVE), 설정 오류(Misconfiguration), 시크릿(Secrets), 의존성(SBOM) 종합 정적 분석.
   - Google Gemini AI를 연동하여 이번 PR 코드 변경 내역(Diff)에서 취약한 라이브러리가 실제로 호출(Reachability)되는지 여부 및 비즈니스 로직 취약점(SSRF, 하드코딩된 토큰, 권한 우회 등) 검출.
   - Node2Shell, 구버전 Dockerfile Base Image, Spring Boot/Java 버전 결함 등 런타임 환경 취약점 동시 진단.

2. **GitHub Checks API 연동을 통한 브랜치 병합(Merge) 차단**
   - 스캔 시작 시 `PR Guard / Security Scan` 상태를 `in_progress`로 등록.
   - 치명적 취약점(CRITICAL/HIGH) 발견 시 `failure`(BLOCK) 마킹으로 GitHub의 **Merge 버튼을 비활성화(원천 차단)**하고 `security-risk` 라벨 자동 부착.
   - 안전 검증 완료 시 `success`(PASS)로 자동 전환되어 안전한 병합 보장.

3. **엔터프라이즈 가독성 최적화 PR 리포트**
   - GitHub Alerts(`[!CAUTION]`, `[!WARNING]`, `[!TIP]`) 기반 최상단 단일 마스터 배너 제공.
   - 불필요한 이모지를 배제한 정돈된 텍스트 중심 헤더.
   - GitHub Copilot Autofix 스타일의 `diff` 코드 수정 가이드 자동 제시.
   - 직접/간접 의존성이 라이선스와 함께 분리된 소프트웨어 자재 명세서(SBOM) 인벤토리 부록 자동 첨부 (토큰 0 소모).

4. **ChatOps 재스캔 명령어 지원**
   - PR 댓글 창에 `@prguard rescan` 또는 `/rescan` 입력 시 봇이 눈 모양(👀) 반응을 남긴 후 최신 커밋을 즉시 비동기 재스캔.

5. **사용자 커스텀 보안 정책 (`.prguard.yml`) 지원**
   - 저장소 루트의 `.prguard.yml` 파일을 통해 조직별 예외 심각도, 예외 패키지, 특정 CVE 무시 및 차단 기준을 유연하게 설정.

---

## 시스템 아키텍처 (Architecture)

```mermaid
sequenceDiagram
    autonumber
    actor Dev as 개발자
    participant GH as GitHub (PR / Webhook)
    participant Server as PR Guard Server
    participant Trivy as Trivy Scanner Engine
    participant Gemini as Google Gemini AI

    Dev->>GH: PR 생성 / 커밋 푸시 / "@prguard rescan" 댓글
    GH->>Server: Webhook 이벤트 발송 (POST /api/webhook)
    Server-->>GH: 202 Accepted (비동기 처리)

    Server->>GH: Checks API (in_progress 등록)
    Server->>GH: PR Diff 수집
    Server->>Trivy: 격리 환경에서 소스코드 복제 및 정적 스캔 (.prguard.yml 로드)
    Trivy-->>Server: JSON 스캔 결과 + 런타임 설정 컨텍스트

    Server->>Gemini: 스캔 요약 + PR Diff + 런타임 컨텍스트 심층 분석 요청
    Gemini-->>Server: Reachability & Autofix 보안 리포트 반환

    Server->>GH: PR 코멘트 등록 (분석 리포트 + SBOM 토글)
    Server->>GH: Checks API 결과 업데이트 (PASS: success / BLOCK: failure) 및 라벨 부착
```

---

## 빠른 시작 가이드 (Quickstart)

### 1. 일반 사용자: 내 저장소에 30초 만에 적용하기 (Installation)

별도의 서버 설치 없이 공식 GitHub App을 등록하는 것만으로 개인 또는 조직(Org)의 저장소에 즉시 적용할 수 있습니다.

1. **GitHub App 설치 링크 접속**: 👉 **[PR Guard GitHub App 설치하기](https://github.com/apps/pr-guard-pg)**
2. **대상 저장소 선택**:
   - `All repositories` (모든 저장소) 또는 `Only select repositories` (지정한 저장소)를 선택하고 **Install**을 클릭합니다.
3. **설치 완료**:
   - 이제 새로운 PR이 생성되거나 기존 PR에 커밋이 푸시될 때마다 PR Guard가 자동으로 취약점을 분석하고 리포트를 작성합니다.
   - PR 코멘트에 `@prguard rescan`을 입력하면 언제든지 수동으로 즉시 재스캔할 수 있습니다.

---

### 2. 저장소별 커스텀 보안 정책 설정 (`.prguard.yml`)

조직이나 프로젝트마다 보안 기준이 다를 수 있습니다. 검사 대상 저장소의 **루트(최상단) 디렉토리**에 `.prguard.yml` (또는 `.prguard.yaml`) 파일을 추가하면, PR Guard가 이를 자동으로 읽어 맞춤형 보안 정책을 적용합니다.

*(설정 파일이 없으면 기본 엔터프라이즈 정책: `CRITICAL`, `HIGH` 심각도 차단 / 예외 없음 으로 동작합니다)*

```yaml
# .prguard.yml 예시
version: 1

# 1. 스캔 및 리포트에서 완전히 무시할 취약점 심각도 (예: LOW, MEDIUM)
ignore_severities:
  - LOW
  - MEDIUM

# 2. 알려진 안전한 내부 패키지 또는 테스트 라이브러리 예외 처리
ignore_packages:
  - "my-company-internal-core"
  - "debug"

# 3. 조치가 불필요하거나 오탐(False Positive)으로 확인된 특정 CVE 예외 처리
ignore_cves:
  - "CVE-2023-9999"

# 4. PR Merge를 강제로 차단(Checks Failure & security-risk 라벨)할 심각도 기준
# 기본값: [CRITICAL, HIGH]
block_severities:
  - CRITICAL
  - HIGH
```

#### 💡 커스텀 설정이 작동하는 방식:
- **Trivy 엔진 필터링:** `ignore_severities`, `ignore_packages`, `ignore_cves`에 해당하는 취약점은 리포트 및 카운트에서 사전에 제외됩니다.
- **AI 시스템 프롬프트 반영:** 사용자가 정의한 정책이 Google Gemini AI의 시스템 프롬프트에 **[저장소 커스텀 예외 룰]**로 실시간 주입되어, 봇이 해당 정책을 인지하고 맥락에 맞게 리뷰 코멘트를 작성합니다.
- **GitHub Checks 통제:** `block_severities`에 지정된 레벨의 취약점이 diff 상에서 실제 호출(Reachability)되는 경우에만 PR 병합을 Block(Checks failure)합니다.

---

### 3. 서버 자체 호스팅 및 개발자 가이드 (Self-Hosting & Development)

직접 백엔드 서버를 구동하거나 커스터마이징하려는 개발자를 위한 가이드입니다.

#### 요구사항 (Prerequisites)
- Java 17 이상
- [Aqua Security Trivy CLI](https://aquasecurity.github.io/trivy/)
- [Google Gemini API Key](https://aistudio.google.com/)
- GitHub App (Private Key `.pem` 파일 발급)

#### 환경 설정
`src/main/resources/application.properties.example` 파일을 복사하여 환경 변수 또는 `src/main/resources/application-local.properties`를 생성합니다 (로컬 설정 파일은 `.gitignore`에 의해 안전하게 제외됩니다):

```properties
# src/main/resources/application-local.properties
gemini.api.key=YOUR_GEMINI_API_KEY
github.app.id=YOUR_GITHUB_APP_ID
github.app.private-key-path=YOUR_GITHUB_APP_PRIVATE_KEY.pem
```

환경 변수로 직접 주입할 수도 있습니다:
- `GEMINI_API_KEY`: Google Gemini API 키
- `GITHUB_APP_ID`: GitHub App ID
- `GITHUB_APP_PRIVATE_KEY` 또는 `GITHUB_APP_PRIVATE_KEY_PATH`: GitHub App RSA 개인키
- `GITHUB_WEBHOOK_SECRET`: GitHub Webhook Secret (선택)

#### 빌드 및 실행
```bash
# 빌드 및 테스트
./gradlew clean test

# 애플리케이션 실행
./gradlew bootRun
```

#### Docker 배포
```bash
docker build -t pr-guard-server .
docker run -p 8080:8080 \
  -e GEMINI_API_KEY=your_key \
  -e GITHUB_APP_ID=your_id \
  -e GITHUB_APP_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----..." \
  pr-guard-server
```

---

## 라이선스 (License)

This project is licensed under the MIT License.

