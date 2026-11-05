<div align="center">

# 🛡️ PR Guard

<p align="center">
  <b>DevSecOps AI Security Gatekeeper & Automated PR Code Reviewer</b><br />
  오픈소스 취약점(CVE), 런타임 환경 결함, 하드코딩된 시크릿을 전수 분석하고<br />
  GitHub Checks API & 공식 PR Review로 위험 코드의 병합(Merge)을 완벽 차단하는 차세대 AI 보안 게이트키퍼
</p>

<p align="center">
  <a href="#-30초-만에-내-저장소에-설치하기-quick-install"><b>빠른 설치</b></a> ·
  <a href="#-실제-pr-리뷰-리포트-예시"><b>리포트 미리보기</b></a> ·
  <a href="#-핵심-기능-key-features"><b>핵심 기능</b></a> ·
  <a href="#-저장소별-맞춤-보안-정책-prguardyml"><b>커스텀 정책</b></a> ·
  <a href="#-chatops-재스캔-명령어"><b>ChatOps</b></a> ·
  <a href="#-시스템-아키텍처-architecture"><b>아키텍처</b></a> ·
  <a href="#-자체-호스팅-가이드-self-hosting"><b>자체 호스팅</b></a>
</p>

<p align="center">
  <a href="https://github.com/apps/pr-guard-pg"><img src="https://img.shields.io/badge/GitHub%20App-pr--guard--pg-2ea44f?style=for-the-badge&logo=github&logoColor=white" alt="GitHub App" /></a>
  <a href="https://www.oracle.com/java/"><img src="https://img.shields.io/badge/Java-17-ED8B00?style=for-the-badge&logo=openjdk&logoColor=white" alt="Java 17" /></a>
  <a href="https://spring.io/projects/spring-boot"><img src="https://img.shields.io/badge/Spring%20Boot-3.4-6DB33F?style=for-the-badge&logo=springboot&logoColor=white" alt="Spring Boot 3.4" /></a>
  <a href="https://aquasecurity.github.io/trivy/"><img src="https://img.shields.io/badge/Scanner-Aqua%20Trivy-007ACC?style=for-the-badge" alt="Aqua Trivy" /></a>
  <a href="https://deepmind.google/technologies/gemini/"><img src="https://img.shields.io/badge/AI%20Engine-Gemini%202.0%20Flash-4285F4?style=for-the-badge&logo=google&logoColor=white" alt="Google Gemini" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg?style=for-the-badge" alt="License: MIT" /></a>
</p>

<p align="center">
  <a href="https://github.com/apps/pr-guard-pg">
    <img src="https://img.shields.io/badge/🚀%20Add%20to%20GitHub-Install%20PR%20Guard-238636?style=for-the-badge&logo=github&logoColor=white" alt="Install PR Guard GitHub App" height="42" />
  </a>
</p>

</div>

---

## 📌 왜 PR Guard인가요?

기존 정적 분석 도구(Snyk, SonarQube 등)는 수백 개의 경고를 쏟아내어 개발자에게 극심한 **알림 피로(Alert Fatigue)**를 유발합니다. 또한 "단순히 취약한 버전이 설치된 것"과 **"실제 이번 PR 변경 코드에서 그 취약점이 호출되는지(Reachability)"**를 구분하지 못합니다.

| 비교 항목 | 기존 보안 점검 도구 | 🛡️ **PR Guard** |
|---|---|---|
| **도입 방식** | 복잡한 CI/CD 스크립트 작성 및 Secret 토큰 등록 | 👉 **클릭 1번으로 GitHub App 설치 완료 (Public & Private 레포 모두 지원)** |
| **도달 가능성 (Reachability)** | 미지원 (사용 여부 무관 단순 경고 남발) | 🧠 **Diff 코드 분석으로 실제 취약점 호출 여부 판별 (False Positive 원천 제거)** |
| **코드 라인별 인라인 리뷰** | 대시보드 링크만 제공 | 💬 **문제 코드 라인에 직접 인라인 코멘트 및 1-Click 수정 패치(`suggestion`) 제공** |
| **Files Changed 어노테이션** | 미지원 | 📌 **GitHub Checks Annotation 연동으로 파일 변경 화면에서 결함 즉시 가시화** |
| **브랜치 병합 통제 (Gatekeeping)** | 코멘트만 남기고 방치되거나 CI 전체 실패 | 🚦 **GitHub Checks API + 공식 PR Review (APPROVE/REQUEST_CHANGES) 연동** |
| **소프트웨어 자재 명세서 (SBOM)** | Lock 파일 필수 (Gradle, C/C++, Mobile 미탐지) | 🌐 **Lock 파일 없는 C/C++, C#, Unity, Mobile, Gradle 등 전 언어 매니페스트 자동 감지 & 합성** |
| **댓글 관리 (UX)** | 커밋 푸시마다 새 댓글 생성 (PR 댓글창 도배) | 🔄 **In-place Upsert: 기존 리포트 코멘트 제자리 자동 갱신 (Spam 방지)** |
| **상호작용 (ChatOps & UI)** | 코드 재수정 및 빈 커밋 푸시 필요 | 💬 **댓글에 `@prguard rescan` 입력 또는 GitHub UI [Re-run] 버튼 클릭 시 즉시 재스캔** |
| **AI 장애 자가 복구 (Self-Healing)** | 외부 AI 503/429 장애 시 CI 중단/크래시 | 🛡️ **지수 백오프 다중 모델 Fallback & Trivy 정적 분석 기반 무중단 자가 복구 리포트** |
| **웹훅 보안 & 엔터프라이즈** | 서명 검증 누락 및 Fork PR 실패 | 🔒 **HMAC SHA-256 서명 검증, GitHub Enterprise Server(GHES) 및 Private 저장소 완벽 지원** |

---

## 🚀 30초 만에 내 저장소에 설치하기 (Quick Install)

서버 설치나 복잡한 YAML 파이프라인 작성 없이, **공식 GitHub App을 등록하는 것만으로 퍼블릭(Public) 및 프라이빗(Private) 저장소에 즉시 적용**할 수 있습니다.

1. **GitHub App 설치 링크 접속**  
   👉 **[PR Guard GitHub App 설치하기](https://github.com/apps/pr-guard-pg)**
2. **적용할 저장소 선택**  
   - `All repositories` (모든 저장소) 또는 `Only select repositories` (특정 저장소)를 선택하고 **Install** 클릭.
3. **설치 완료!**  
   - 이제 새로운 PR을 열거나 커밋을 푸시할 때마다 PR Guard가 자동으로 취약점을 분석하고 리뷰를 작성합니다.

---

## 📋 실제 PR 리뷰 리포트 및 인라인 코멘트 예시

PR Guard는 개발자의 가독성을 극대화하기 위해 불필요한 이모지 남발을 배제하고, **GitHub Alerts 표준 문법**, **코드 라인별 인라인 코멘트**, **GitHub Copilot 스타일의 Diff 제안**을 제공합니다.

### 1. PR 메인 종합 리포트 코멘트 (차단 권고 시)

> [!CAUTION]
> ### 차단 권고 (BLOCK)
> 이번 변경 사항에서 원격 코드 실행(RCE) 및 인증 우회가 가능한 치명적 보안 위협이 확인되어 브랜치 병합을 차단합니다.
>
> - **오픈소스 취약점 (CVE):** 총 1건 (CRITICAL 1건)
> - **코드 로직 및 설정 결함:** 총 1건 (시크릿 하드코딩 노출)

---

#### 1. 오픈소스 취약점 (CVE) — 총 1건 (CRITICAL 1건)

<details open>
<summary><b>상세 취약점 내역 및 패치 가이드 보기</b></summary>

- **[1순위] `org.springframework:spring-beans` (CVE-2022-22965 / 위험도: CRITICAL)**
  - **호출 여부:** 실제 호출됨 (`UserController.java`의 데이터 바인딩 로직에서 악용 가능)
  - **위협 요약:** ClassLoader 조작을 통한 원격 임의 코드 실행(RCE, Spring4Shell)
  - **조치:** `5.3.17` ➔ `5.3.18` 이상 또는 Spring Boot `2.6.6` 이상으로 업그레이드

**(패치 명령어)**
```bash
./gradlew dependencyUpdates
```

</details>

---

#### 2. 소프트웨어 자재 명세서 (SBOM) 전수 인벤토리

<details>
<summary><b>소프트웨어 자재 명세서 (SBOM) 구성 요소 보기 (총 42개 컴포넌트)</b></summary>

| 구분 | 패키지명 | 설치 버전 | 라이선스 |
|:---|:---|:---|:---|
| 직접 의존성 | `org.springframework.boot:spring-boot-starter-web` | `2.6.6` | Apache-2.0 |
| 직접 의존성 | `com.fasterxml.jackson.core:jackson-databind` | `2.15.2` | Apache-2.0 |
| 직접 의존성 | `io.jsonwebtoken:jjwt-api` | `0.12.6` | Apache-2.0 |
| 간접 의존성 | `ch.qos.logback:logback-classic` | `1.4.11` | EPL-1.0 |

</details>

---

### 2. 코드 라인별 인라인 리뷰 코멘트 (Files Changed 화면)

취약점이나 시크릿 노출이 포함된 코드 라인에 **직접 인라인 코멘트**가 등록되며, **1-Click 버튼으로 즉시 반영할 수 있는 수정 제안**이 제공됩니다:

```markdown
⚠️ **[PR Guard 보안 경고]** 하드코딩된 시크릿/토큰 감지 (`JWT Secret Key`)
> **위험도:** `CRITICAL` (규칙 ID: `generic-jwt-secret`)
> 
> 코드 내에 인증 정보나 암호키가 직접 노출되었습니다. GitHub 저장소에 커밋되면 즉시 유출 사고로 이어질 수 있습니다.
> `System.getenv()`, `process.env` 등 환경 변수 또는 Secret Manager를 통해 주입받도록 수정해 주세요.

```suggestion
+ const jwtSecret = process.env.JWT_SECRET;
```
```

---

### 3. 검증 통과 리포트 (안전 상태 - 승인)

> [!TIP]
> ### 승인 (PASS)
> 오픈소스 취약점(CVE), 런타임 환경, 설정 오류 및 코드 내 보안 위협이 발견되지 않았습니다.
>
> - **오픈소스 취약점 (CVE):** 0건 (안전)
> - **코드 로직 및 설정 결함:** 0건 (안전)

---

## ✨ 핵심 기능 (Key Features)

### 1. Reachability & 비즈니스 로직 심층 분석
- Aqua Security Trivy 엔진의 취약점 분석 데이터와 PR Diff 코드를 결합.
- **Google Gemini 2.0 Flash**가 Diff 상에서 취약 함수가 실제로 호출(Reachability)되는지 판별하여 **거짓 양성(False Positive) 제거**.
- Node2Shell, 구버전 Dockerfile 베이스 이미지, 루트 계정 실행, 시크릿 하드코딩, SSRF 위험 등 런타임 환경 결함 동시 탐지.

### 2. 비공개(Private) 저장소 완벽 지원 & 보안 격리
- GitHub App **Installation Access Token (`ghs_...`)**을 동적 발급하여 비공개 저장소도 프롬프트 멈춤 없이 안전하게 Clone.
- 스캔 완료 즉시 임시 디렉토리 및 메모리를 완전 파기(Clean-up)하며, 로그에 토큰이 절대 노출되지 않도록 마스킹(`ghs_***`) 처리.

### 3. 공식 GitHub PR Review & Checks API 브랜치 보호 연동
- **공식 PR Review:** 판정 결과에 따라 `APPROVE`, `REQUEST_CHANGES`, `COMMENT` 이벤트를 공식 제출하여 GitHub 브랜치 보호 규칙(`Require a pull request review before merging`)과 완벽하게 호환됩니다.
- **Checks API & Commit Status:** `PR Guard / Security Scan` Check Run 및 `pr-guard/security` 컨텍스트 상태를 실시간 동기화하여 고위험 취약점 발견 시 **Merge 버튼을 원천 비활성화**하고 `security-risk` 라벨을 자동 부착합니다.
- **Files Changed 어노테이션:** Check Run Annotation(최대 50건)을 전송하여 파일 변경 탭에서 위험 위치를 한눈에 파악할 수 있습니다.

### 4. Lock 파일 없는 프로젝트 전방위 지원 (Universal Dependency Scanner)
- Lock 파일(`package-lock.json`, `poetry.lock` 등)이 없는 프로젝트에서도 소프트웨어 자재 명세서(SBOM)를 완벽하게 인벤토리화합니다.
- **지원 생태계:**
  - Java / Kotlin: `build.gradle`, `build.gradle.kts`, `pom.xml`
  - C / C++: `CMakeLists.txt`, `conanfile.txt`, `vcpkg.json`
  - C# / .NET: `.csproj`, `packages.config`
  - 모바일 / 크로스플랫폼: Flutter (`pubspec.yaml`), iOS CocoaPods (`Podfile`)
  - 게임 엔진: Unity (`Packages/manifest.json`)
  - 스크립트 / 시스템: Python (`requirements.txt`, `pyproject.toml`), Rust (`Cargo.toml`), Go (`go.mod`), PHP (`composer.json`), Ruby (`Gemfile`)

### 5. 댓글 도배 방지 (In-place Upsert)
- 개발자가 커밋을 연속 푸시하거나 재스캔을 요청할 때마다 새로운 댓글을 누적 생성하지 않습니다.
- 기존에 등록된 PR Guard 코멘트를 GitHub Issue Comment PATCH API로 제자리 갱신하여 **PR 대화창의 가독성을 언제나 깔끔하게 유지**합니다.

### 6. 무중단 자가 복구 엔진 (Zero-Crash Fallback)
- Google AI 서비스의 일시적 트래픽 스파이크(503 High Demand / 429 Rate Limit) 발생 시 지수 백오프(1.2초, 2.4초)로 자동 재시도합니다.
- 모든 AI 모델이 일시 중단되더라도, Trivy 정적 보안 엔진의 전수 분석 결과를 기반으로 **PASS / WARN / BLOCK을 자체 판정하는 Fallback 리포트를 자동 생성**하여 체크 런이 실패(`Action Required`)로 떨어지는 일을 원천 방지합니다.

### 7. 양방향 ChatOps 및 GitHub UI Re-run 연동
- PR 댓글 창에 `@prguard rescan` 또는 `/rescan` 입력 시 봇이 눈 모양(👀) 리액션을 남긴 후 최신 커밋을 즉시 비동기 재스캔.
- `@prguard help` 명령어로 지원 기능 및 사용 가능한 명령어 안내 출력.
- GitHub Checks 탭의 **[Re-run]** 버튼을 클릭해도 웹훅(`check_run: rerequested`)을 감지하여 즉시 재스캔 실행.

---

## ⚙️ 저장소별 맞춤 보안 정책 (`.prguard.yml`)

조직이나 팀마다 보안 표준이 다를 수 있습니다. 검사 대상 저장소의 **최상단(루트 디렉토리)**에 `.prguard.yml` (또는 `.prguard.yaml`) 파일을 추가하면, PR Guard가 이를 자동으로 감지하여 맞춤형 보안 정책을 적용합니다.

*(설정 파일이 없으면 기본 엔터프라이즈 정책: `CRITICAL`, `HIGH` 심각도 차단 / 예외 없음으로 동작합니다)*

```yaml
# .prguard.yml
version: 1

# 1. 스캔 및 리포트에서 완전히 제외할 취약점 심각도
ignore_severities:
  - LOW
  - MEDIUM

# 2. 알려진 안전한 내부 공통 패키지 또는 테스트 라이브러리 예외 처리
ignore_packages:
  - "my-internal-core-ui"
  - "debug"

# 3. 조치가 불필요하거나 오탐으로 확인된 특정 CVE 예외 처리
ignore_cves:
  - "CVE-2023-9999"

# 4. PR Merge를 강제로 차단(Checks Failure)할 심각도 기준
# 기본값: [CRITICAL, HIGH]
block_severities:
  - CRITICAL
  - HIGH
```

---

## 💬 ChatOps 및 인터랙션 가이드

개발 중 PR 댓글 창이나 GitHub UI를 통해 아래 기능을 활용할 수 있습니다:

| 액션 / 명령어 | 설명 |
|---|---|
| `@prguard rescan` 또는 `/rescan` | 봇이 댓글에 즉시 👀 리액션을 달고, 최신 브랜치를 다시 Clone하여 처음부터 보안 검사를 재실행합니다. |
| `@prguard help` 또는 `/help` | 사용 가능한 명령어 및 지원 기능 안내 도움말 코멘트를 출력합니다. |
| GitHub Checks UI **[Re-run]** 클릭 | 댓글 작성 없이 GitHub UI에서 바로 이전 스캔을 다시 실행합니다. |

---

## 🏗️ 시스템 아키텍처 (Architecture)

```mermaid
sequenceDiagram
    autonumber
    actor Dev as 개발자
    participant GH as GitHub (PR / Checks / Reviews)
    participant Server as PR Guard Server (Spring Boot)
    participant Trivy as Aqua Trivy & Universal Scanner
    participant Gemini as Google Gemini AI (Fallback 체인)

    Dev->>GH: PR 생성 / 커밋 푸시 / "@prguard rescan" 댓글 / UI Re-run
    GH->>Server: Webhook 이벤트 발송 (POST /api/webhook)
    Server-->>GH: 202 Accepted (HMAC 검증 후 비동기 파이프라인 즉시 시작)

    Server->>GH: Checks API (in_progress 등록)
    par 병렬 데이터 수집
        Server->>GH: PR Diff 코드 및 변경 파일 목록 수집
    and
        Server->>Trivy: 격리 환경에서 소스코드 복제 및 정적 스캔 (.prguard.yml 반영)
        Trivy-->>Server: JSON 취약점 데이터 + 범용 SBOM + 런타임 설정 컨텍스트
    end

    Server->>Gemini: 스캔 결과 + PR Diff + 런타임 설정 심층 분석 요청
    alt Gemini 정상 응답
        Gemini-->>Server: Reachability 판별 & 1-Click 제안 리포트 반환
    else Google AI 503/429 장애 시
        Server->>Server: Trivy 전수 검사 기반 자가 복구 리포트(Fallback) 자동 생성
    end

    Server->>GH: PR 리포트 코멘트 작성 (기존 코멘트 존재 시 PATCH Upsert)
    Server->>GH: 코드 라인별 인라인 리뷰 코멘트 (1-Click Suggestion) 등록
    Server->>GH: Checks API 어노테이션(최대 50건) & Commit Status 동기화
    Server->>GH: 공식 PR Review (PASS: APPROVE / BLOCK: REQUEST_CHANGES) 제출 및 라벨 부착
```

---

## 🚀 CI/CD & 무중단 자동 배포 (GitHub Actions)

PR Guard 서버 저장소는 `main` 브랜치에 코드가 머지되면 **GitHub Actions**가 자동으로 단위 테스트를 검증하고 Render에 무중단 배포를 트리거합니다.

### 배포 파이프라인 흐름 ([`.github/workflows/deploy.yml`](.github/workflows/deploy.yml))
1. **CI 품질 게이트 (Quality Gate):** 머지 직후 `./gradlew test --no-daemon`을 실행하여 단위 테스트가 100% 통과할 때만 배포가 승인됩니다.
2. **Render Deploy Hook 호출:** GitHub Secrets에 등록된 `RENDER_DEPLOY_HOOK_URL`로 배포 트리거 요청을 전송합니다.
3. **헬스체크 검증:** 배포 후 `https://pr-guard-server.onrender.com/api/ping` 엔드포인트를 호출하여 서버 생존을 확인합니다.

---

## 💻 자체 호스팅 가이드 (Self-Hosting)

사내 폐쇄망 환경이나 자체 클라우드(AWS, GCP, Oracle Cloud, Render 등)에 PR Guard 서버를 직접 구축하려는 개발자를 위한 가이드입니다.

### 요구사항 (Prerequisites)
- Java 17+
- [Aqua Security Trivy CLI](https://aquasecurity.github.io/trivy/)
- [Google Gemini API Key](https://aistudio.google.com/)
- GitHub App 등록 (Private Key `.pem` 파일 발급)

### 필수 GitHub App 권한 (Permissions)
GitHub App 생성 시 아래 권한을 부여해야 모든 기능이 정상 동작합니다:

| 권한 항목 | 접근 수준 (Access) | 사용 목적 |
|---|---|---|
| **Pull requests** | `Read and write` | PR Diff 코드 조회, 인라인 리뷰 코멘트 등록 및 공식 PR Review 제출 |
| **Issues** | `Read and write` | 종합 분석 리포트 코멘트 작성(Upsert), 라벨 부여 및 ChatOps 감지 |
| **Checks** | `Read and write` | Check Run 등록, 어노테이션(최대 50건) 전송 및 브랜치 병합 차단 통제 |
| **Commit statuses** | `Read and write` | 브랜치 보호 규칙 호환 커밋 Status 동기화 (`pr-guard/security`) |
| **Contents** | `Read-only` | PR 대상 소스코드 Git Clone (Public & Private 레포 공통 필수) |
| **Metadata** | `Read-only` | 기본 저장소 정보 확인 (기본 활성화) |
| **이벤트 구독** | `Pull request`, `Issue comment`, `Check run`, `Check suite` | 웹훅 이벤트 수신 |

### 환경 변수 설정 (Environment Variables)

`src/main/resources/application.properties.example`을 참고하여 환경 변수를 주입합니다:

| 환경 변수명 | 필수 여부 | 기본값 | 설명 |
|---|---|---|---|
| `GEMINI_API_KEY` | **필수** | - | Google AI Studio에서 발급받은 Gemini API 키 |
| `GEMINI_MODEL` | 선택 | `gemini-2.0-flash` | 사용할 Gemini 모델 (`gemini-2.0-flash`, `gemini-1.5-flash` 등) |
| `GEMINI_API_URL` | 선택 | `https://generativelanguage.googleapis.com/v1beta/models` | Gemini API 엔드포인트 URL (사내 AI 프록시 연동 지원) |
| `GITHUB_APP_ID` | **필수** | - | 등록한 GitHub App의 고유 ID |
| `GITHUB_APP_PRIVATE_KEY` | 선택 | - | GitHub App의 RSA Private Key 원문 (`-----BEGIN RSA...`) |
| `GITHUB_APP_PRIVATE_KEY_PATH` | 선택 | `(자동 탐색)` | Private Key 파일 마운트 경로 (미설정 시 `/etc/secrets`, classpath, 루트의 `*.pem` 자동 감지) |
| `GITHUB_WEBHOOK_SECRET` | 선택 | - | Webhook HMAC SHA-256 서명 검증 시크릿 (설정 시 위조 요청 차단) |
| `GITHUB_API_URL` | 선택 | `https://api.github.com` | GitHub API 엔드포인트 (**GitHub Enterprise Server 완벽 호환**) |
| `GITHUB_CHECK_RUN_NAME` | 선택 | `PR Guard / Security Scan` | GitHub Checks 탭에 표시될 체크 런 이름 |
| `GITHUB_STATUS_CONTEXT` | 선택 | `pr-guard/security` | GitHub Commit Status 컨텍스트 이름 |
| `GITHUB_BOT_NAME` | 선택 | `prguard` | ChatOps 봇 호출 멘션 이름 (`@prguard rescan`, `@prguard help`) |
| `GITHUB_SECURITY_LABEL` | 선택 | `security-risk` | 보안 결함 검출 시 PR에 부여할 라벨명 |
| `TRIVY_PROCESS_TIMEOUT_MINUTES` | 선택 | `5` | Git Clone 및 Trivy 스캔 프로세스 타임아웃(분) |
| `TRIVY_DB_UPDATE_INTERVAL_HOURS` | 선택 | `12` | Trivy 취약점 DB 업데이트 주기(시간) |
| `DIFF_MAX_LENGTH` | 선택 | `15000` | 분석 대상 PR Diff 최대 길이(자) |
| `MAX_INLINE_COMMENTS` | 선택 | `5` | PR 당 최대 등록할 취약점 인라인 코멘트 수 |
| `RENDER_DEPLOY_HOOK_URL` | 선택 | - | `main` 머지 시 Render 자동 배포를 트리거할 Deploy Hook URL |
| `PORT` | 선택 | `8080` | 서버 HTTP 포트 |

### 로컬 빌드 및 실행
```bash
# 빌드 및 전체 테스트
./gradlew clean test

# 스프링 부트 애플리케이션 실행
./gradlew bootRun
```

### Docker 실행
```bash
# Docker 이미지 빌드 (Trivy 취약점 DB가 이미지 내에 사전 내장됩니다)
docker build -t pr-guard-server .

# 컨테이너 실행 (비루트 appuser 실행 및 헬스체크 내장)
docker run -d -p 8080:8080 \
  -e GEMINI_API_KEY="your_gemini_api_key" \
  -e GITHUB_APP_ID="your_github_app_id" \
  -e GITHUB_APP_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----..." \
  -e GITHUB_WEBHOOK_SECRET="your_webhook_secret" \
  --name pr-guard-server pr-guard-server
```

---

## 📄 라이선스 (License)

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.
