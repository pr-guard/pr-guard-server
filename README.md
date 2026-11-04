<div align="center">

# 🛡️ PR Guard

<p align="center">
  <b>DevSecOps AI Security Gatekeeper & Automated PR Code Reviewer</b><br />
  오픈소스 취약점(CVE), 런타임 환경 결함, 시크릿 노출을 정밀 분석하고<br />
  GitHub Checks API를 통해 위험 코드의 병합(Merge)을 원천 차단하는 AI 보안 게이트키퍼
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
  <a href="https://spring.io/projects/spring-boot"><img src="https://img.shields.io/badge/Spring%20Boot-3.2-6DB33F?style=for-the-badge&logo=springboot&logoColor=white" alt="Spring Boot 3.2" /></a>
  <a href="https://aquasecurity.github.io/trivy/"><img src="https://img.shields.io/badge/Scanner-Aqua%20Trivy-007ACC?style=for-the-badge" alt="Aqua Trivy" /></a>
  <a href="https://deepmind.google/technologies/gemini/"><img src="https://img.shields.io/badge/AI%20Engine-Gemini%201.5%20Pro-4285F4?style=for-the-badge&logo=google&logoColor=white" alt="Google Gemini" /></a>
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

기존 정적 분석 도구(Snyk, SonarQube 등)는 수백 개의 경고를 쏟아내어 개발자에게 극심한 **알림 피로(Alert Fatigue)**를 유발합니다. 또한 "단순히 취약한 버전이 깔려있는 것"과 **"실제 이번 PR 변경 코드에서 그 취약점이 호출되는지(Reachability)"**를 구분하지 못합니다.

| 비교 항목 | 기존 보안 점검 도구 | 🛡️ **PR Guard** |
|---|---|---|
| **도입 방식** | 복잡한 CI/CD 스크립트 작성 및 Secret 등록 | 👉 **클릭 1번으로 GitHub App 설치 완료** |
| **도달 가능성 (Reachability)** | 미지원 (사용 여부 무관 단순 경고 남발) | 🧠 **Diff 코드 분석으로 실제 취약점 호출 여부 판별** |
| **코드 수정 가이드** | "업데이트하세요" 텍스트 안내 | 💡 **복사 가능한 `diff` 수정 코드 즉시 제안** |
| **병합(Merge) 통제** | 코멘트만 남기고 방치되거나 CI 전체 실패 | 🚦 **GitHub Checks API로 치명적 위험만 지능적 차단** |
| **상호작용 (ChatOps)** | 코드 재수정 및 빈 커밋 푸시 필요 | 💬 **댓글에 `@prguard rescan` 입력 시 즉시 재스캔** |
| **운영 비용** | 유료 엔터프라이즈 구독 필요 | 🆓 **무료 오픈소스 및 GitHub App 즉시 사용 가능** |

---

## 🚀 30초 만에 내 저장소에 설치하기 (Quick Install)

서버 설치나 복잡한 YAML 파이프라인 작성 없이, **공식 GitHub App을 등록하는 것만으로 개인 또는 조직(Org)의 저장소에 즉시 적용**할 수 있습니다.

1. **GitHub App 설치 링크 접속**  
   👉 **[PR Guard GitHub App 설치하기](https://github.com/apps/pr-guard-pg)**
2. **적용할 저장소 선택**  
   - `All repositories` (모든 저장소) 또는 `Only select repositories` (특정 저장소)를 선택하고 **Install** 클릭.
3. **설치 완료!**  
   - 이제 새로운 PR을 열거나 커밋을 푸시할 때마다 PR Guard가 자동으로 취약점을 분석하고 리뷰를 작성합니다.

---

## 📋 실제 PR 리뷰 리포트 예시

PR Guard는 개발자의 가독성을 극대화하기 위해 불필요한 이모지 남발을 줄이고, **GitHub Alerts 표준 문법**과 **GitHub Copilot 스타일의 Diff 제안**을 제공합니다.

### 🔴 위험 감지 시 (CRITICAL / HIGH 탐지 및 Merge 차단)

> [!CAUTION]
> ### 치명적 보안 위험 감지 (BLOCK)
> 이번 변경 사항에서 **원격 코드 실행(RCE)**이 가능한 1건의 취약 라이브러리가 직접 호출(Reachability)되고 있어 메인 브랜치 병합을 차단합니다.
>
> **오픈소스 취약점 (CVE):** 총 1건 (차단 1건)  
> **코드 로직 및 설정 결함:** 총 0건

<details open>
<summary><b>1. 직접 도달 가능한 취약점 — 1건 (상세 보기)</b></summary>

- **CVE-2022-22965 (Spring4Shell)**: `org.springframework:spring-beans`  
  - **심각도:** `CRITICAL` (CVSS 9.8)  
  - **호출 분석:** `UserController.java`의 `@ModelAttribute` 바인딩 로직에서 데이터 바인딩 취약 매개변수가 외부 입력에 그대로 노출되어 원격 코드 실행이 가능합니다.  
  - **조치 권고:** Spring Framework `5.3.18` 이상 또는 Spring Boot `2.6.6` 이상으로 즉시 업그레이드하십시오.

```diff
// build.gradle 수정 제안
- implementation 'org.springframework.boot:spring-boot-starter-web:2.6.5'
+ implementation 'org.springframework.boot:spring-boot-starter-web:2.6.6'
```
</details>

<details>
<summary><b>📦 소프트웨어 자재 명세서 (SBOM) — 총 42개 컴포넌트</b></summary>

| 구분 | 패키지명 | 버전 | 라이선스 |
|---|---|---|---|
| 직접 의존성 | `org.springframework.boot:spring-boot-starter-web` | `2.6.6` | Apache-2.0 |
| 직접 의존성 | `com.fasterxml.jackson.core:jackson-databind` | `2.15.2` | Apache-2.0 |
| 간접 의존성 | `ch.qos.logback:logback-classic` | `1.4.11` | EPL-1.0 |

</details>

---

### 🟢 검증 완료 시 (안전 상태)

> [!TIP]
> ### 보안 검증 통과 (PASS)
> 변경된 코드(Diff)와 연관된 소프트웨어 자재 명세서(SBOM) 및 설정 파일에서 알려진 취약점이나 보안 결함이 검출되지 않았습니다. 안전하게 병합할 수 있습니다.

---

## ✨ 핵심 기능 (Key Features)

### 1. Reachability & 비즈니스 로직 심층 분석
- Aqua Security Trivy 엔진의 취약점/SBOM 분석 데이터와 PR Diff 코드를 결합.
- **Google Gemini 1.5 Pro**가 Diff 상에서 취약 함수가 실제로 호출(Reachability)되는지 판별하여 **거짓 양성(False Positive) 제거**.
- Node2Shell, 구버전 Dockerfile 베이스 이미지, 루트 계정 실행, 시크릿 하드코딩 등 런타임 환경 결함 동시 탐지.

### 2. GitHub Checks API 기반 브랜치 병합(Merge) 차단
- 스캔 시작 시 `PR Guard / Security Scan` Check Run을 `in_progress` 상태로 등록.
- 치명적 취약점 탐지 시 `conclusion: failure`로 전환하여 **GitHub Merge 버튼을 비활성화(원천 차단)**하고 `security-risk` 라벨을 자동 부착.
- 안전 검증 통과 시 `conclusion: success`로 전환되어 안전한 병합 보장.

### 3. ChatOps 재스캔 명령어
- PR 댓글 창에 `@prguard rescan` 또는 `/rescan` 입력 시 봇이 눈 모양(👀) 리액션을 남긴 후 최신 커밋을 즉시 비동기 재스캔.
- 빈 커밋을 푸시할 필요 없이 설정 변경이나 외부 취약점 DB 갱신 시 원클릭 재검증.

### 4. 코드형 보안 정책 (Configuration as Code)
- 저장소 루트에 `.prguard.yml`을 배치하여 조직별 예외 정책(무시할 심각도, 예외 패키지, 특정 CVE 허용, 차단 기준)을 자유롭게 정의.

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

### 💡 커스텀 설정 동작 메커니즘
1. **Trivy 엔진 사전 필터링:** `ignore_`에 지정된 항목은 스캔 결과 목록 및 카운트에서 사전 제거됩니다.
2. **AI 시스템 프롬프트 반영:** 사용자가 정의한 정책이 Google Gemini AI의 시스템 프롬프트에 **`[저장소 커스텀 예외 룰]`**로 주입되어 불필요한 알림을 방지합니다.
3. **GitHub Checks 통제:** `block_severities`에 설정된 등급의 위험이 Diff 상에서 실제 호출될 때만 병합을 Block합니다.

---

## 💬 ChatOps 재스캔 명령어

개발 중 PR 댓글 창에 아래 명령어를 입력하여 파이프라인을 트리거할 수 있습니다:

| 명령어 | 동작 설명 |
|---|---|
| `@prguard rescan` | 봇이 댓글에 즉시 👀 리액션을 달고, 최신 브랜치를 다시 Clone하여 처음부터 보안 검사를 재실행합니다. |
| `/rescan` | `@prguard rescan`과 동일하게 동작하는 슬래시 단축 명령어입니다. |

---

## 🏗️ 시스템 아키텍처 (Architecture)

```mermaid
sequenceDiagram
    autonumber
    actor Dev as 개발자
    participant GH as GitHub (PR / Webhook)
    participant Server as PR Guard Server (Spring Boot)
    participant Trivy as Aqua Trivy Engine
    participant Gemini as Google Gemini AI

    Dev->>GH: PR 생성 / 커밋 푸시 / "@prguard rescan" 댓글
    GH->>Server: Webhook 이벤트 발송 (POST /api/webhook)
    Server-->>GH: 202 Accepted (비동기 파이프라인 즉시 시작)

    Server->>GH: Checks API (in_progress 등록)
    Server->>GH: PR Diff 코드 및 변경 파일 목록 수집
    Server->>Trivy: 격리 환경에서 소스코드 복제 및 정적 스캔 (.prguard.yml 반영)
    Trivy-->>Server: JSON 취약점 데이터 + SBOM + 런타임 설정 컨텍스트

    Server->>Gemini: 스캔 결과 + PR Diff + 런타임 설정 심층 분석 요청
    Gemini-->>Server: Reachability 판별 & Diff 자동 생성 리포트 반환

    Server->>GH: PR 마크다운 리포트 코멘트 작성
    Server->>GH: Checks API 업데이트 (PASS: success / BLOCK: failure) 및 라벨 부착
```

---

## 💻 자체 호스팅 가이드 (Self-Hosting)

사내 폐쇄망 환경이나 사내 전용 클라우드에 PR Guard 서버를 직접 구축하려는 개발자를 위한 가이드입니다.

### 요구사항 (Prerequisites)
- Java 17+
- [Aqua Security Trivy CLI](https://aquasecurity.github.io/trivy/)
- [Google Gemini API Key](https://aistudio.google.com/)
- GitHub App 등록 (Private Key `.pem` 파일 발급)

### 로컬 환경 설정
`src/main/resources/application.properties.example` 파일을 복사하여 `src/main/resources/application-local.properties`를 생성합니다 (로컬 파일은 `.gitignore`에 의해 안전하게 제외됩니다):

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
- `PORT`: 서버 포트 (기본값: `8080`)

### 로컬 빌드 및 실행
```bash
# 빌드 및 테스트
./gradlew clean test

# 스프링 부트 애플리케이션 실행
./gradlew bootRun
```

### Docker 실행
```bash
# Docker 이미지 빌드
docker build -t pr-guard-server .

# 컨테이너 실행 (비루트 실행 및 헬스체크 내장)
docker run -d -p 8080:8080 \
  -e GEMINI_API_KEY="your_gemini_api_key" \
  -e GITHUB_APP_ID="your_github_app_id" \
  -e GITHUB_APP_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----..." \
  --name pr-guard-server pr-guard-server
```

---

## 📄 라이선스 (License)

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.
