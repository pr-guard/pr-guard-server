package io.github.hanjungho.prguard.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.web.client.RestTemplate;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class LLMAnalysisServiceTest {

    private LLMAnalysisService service;
    private ObjectMapper objectMapper;

    @BeforeEach
    void setUp() {
        objectMapper = new ObjectMapper();
        RestTemplate restTemplate = new RestTemplate();
        service = new LLMAnalysisService(objectMapper, restTemplate);
    }

    @Test
    @DisplayName("취약점 0건이고 다중 Results 구조일 때도 모든 Packages가 정상 파싱되어야 한다")
    void shouldExtractAllPackagesEvenWhenZeroVulnerabilities() {
        String trivyJson = """
                {
                  "SchemaVersion": 2,
                  "Results": [
                    {
                      "Target": "Dockerfile",
                      "Class": "config",
                      "Misconfigurations": []
                    },
                    {
                      "Target": "package-lock.json",
                      "Class": "lang-pkgs",
                      "Type": "npm",
                      "Packages": [
                        {
                          "Name": "react",
                          "Version": "18.2.0",
                          "Indirect": false
                        },
                        {
                          "Name": "loose-envify",
                          "Version": "1.4.0",
                          "Indirect": true
                        }
                      ]
                    }
                  ]
                }
                """;

        LLMAnalysisService.ScanSummaryPayload summary = service.extractScanSummary(trivyJson);

        assertNotNull(summary);
        assertEquals(2, summary.sbomStats().totalCount(), "총 2개의 패키지가 수집되어야 함");
        assertEquals(1, summary.sbomStats().directCount(), "직접 의존성은 1개여야 함");
        assertEquals(1, summary.sbomStats().transitiveCount(), "간접 의존성은 1개여야 함");
        assertEquals(2, summary.sbomPackages().size(), "상세 패키지 목록 크기는 2여야 함");
        assertEquals(0, summary.totalVulnerabilitiesCount(), "취약점은 0건이어야 함");
    }

    @Test
    @DisplayName("Java 자체 생성 소프트웨어 자재 명세서(SBOM) 직접/간접 분리 표 및 라이선스 렌더링 검증")
    void shouldGenerateSbomMarkdownTableCorrectly() {
        List<LLMAnalysisService.SbomPackageDetail> packages = List.of(
                new LLMAnalysisService.SbomPackageDetail("react", "18.2.0", false, "MIT"),
                new LLMAnalysisService.SbomPackageDetail("loose-envify", "1.4.0", true, "Apache-2.0")
        );

        String markdown = service.generateSbomMarkdownTable(packages);

        assertNotNull(markdown);
        assertTrue(markdown.contains("<details>"));
        assertTrue(markdown.contains("<summary><b>소프트웨어 자재 명세서 (SBOM) 구성 요소 보기 (총 2개)</b></summary>"));
        assertFalse(markdown.contains("[!NOTE]"), "깃허브 details 내에서 지원되지 않는 [!NOTE] 태그는 포함되지 않아야 함");
        assertTrue(markdown.contains("> **소프트웨어 구성 요소:** 직접 의존성 1개 / 간접 의존성 1개"));
        assertTrue(markdown.contains("#### 직접 의존성 (Direct Dependencies - 1개)"));
        assertTrue(markdown.contains("| `react` | `18.2.0` | MIT |"));
        assertTrue(markdown.contains("#### 간접 의존성 (Transitive Dependencies - 1개)"));
        assertTrue(markdown.contains("| `loose-envify` | `1.4.0` | Apache-2.0 |"));
        assertTrue(markdown.contains("</details>"));
    }

    @Test
    @DisplayName("안전한 PR(취약점 0건, PR diff 없음)일 때 중복 빈 섹션 없이 승인 배너와 소프트웨어 자재 명세서(SBOM) 표만 결합되어야 한다")
    void shouldAppendSbomTableToApprovedReport() {
        String trivyJson = """
                {
                  "SchemaVersion": 2,
                  "Results": [
                    {
                      "Target": "package-lock.json",
                      "Class": "lang-pkgs",
                      "Packages": [
                        {
                          "Name": "lodash",
                          "Version": "4.17.21",
                          "Indirect": false,
                          "Licenses": ["MIT"]
                        }
                      ]
                    }
                  ]
                }
                """;

        String finalReport = service.analyzeVulnerabilities(trivyJson, "");

        assertNotNull(finalReport);
        assertTrue(finalReport.contains("> [!TIP]"));
        assertTrue(finalReport.contains("### 승인 (PASS)"));
        assertTrue(finalReport.contains("- **오픈소스 취약점 (CVE):** 0건 (안전)"));
        assertTrue(finalReport.contains("- **코드 로직 및 설정 결함:** 0건 (안전)"));
        assertFalse(finalReport.contains("### 1. 오픈소스 취약점 (CVE)"), "안전할 때는 불필요한 빈 섹션 헤더가 없어야 함");
        assertFalse(finalReport.contains("### 2. 코드 로직 및 설정 결함"), "안전할 때는 불필요한 빈 섹션 헤더가 없어야 함");
        assertTrue(finalReport.contains("---"));
        assertTrue(finalReport.contains("<details>"));
        assertTrue(finalReport.contains("<summary><b>소프트웨어 자재 명세서 (SBOM) 구성 요소 보기 (총 1개)</b></summary>"));
        assertTrue(finalReport.contains("#### 직접 의존성 (Direct Dependencies - 1개)"));
        assertTrue(finalReport.contains("| `lodash` | `4.17.21` | MIT |"));
        assertFalse(finalReport.contains("[!NOTE]"));
    }

    @Test
    @DisplayName("이모지 배제, 최상단 단일 마스터 Alert 배너, 서브섹션 위계 분리, 0건 섹션 생략, SBOM 분리 및 diff 개행 규칙 검증")
    void shouldContainRevampedAlertsAndSectionsInPrompt() {
        String prompt = service.buildPrompt("{}", "const test = 1;", "Dockerfile: FROM node:20");

        assertNotNull(prompt);
        // 1. 이모지 배제 및 최상단 단일 Alert 문법 검증
        assertTrue(prompt.contains("모든 이모지(Emoji) 원칙적 배제"));
        assertTrue(prompt.contains("시각적 위계(Visual Hierarchy) 확립 및 최상단 단일 마스터 Alert 배너 적용"));
        assertTrue(prompt.contains("[!TIP]"));
        assertTrue(prompt.contains("[!WARNING]"));
        assertTrue(prompt.contains("[!CAUTION]"));

        // 2. 결함 검출 시에만 서브 섹션 표기 및 <details open> 검증
        assertTrue(prompt.contains("결함이 존재하는 섹션만 상세 표기 및 <details open> 기본 펼침"));
        assertTrue(prompt.contains("0건인 안전한 항목은 하위 세부 섹션을 생성하지 말고 과감히 생략하라"));
        assertTrue(prompt.contains("### 1. 오픈소스 취약점 (CVE) — 총 N건"));
        assertTrue(prompt.contains("### 2. 코드 로직 및 설정 결함 — 총 N건"));
        assertTrue(prompt.contains("<details open>"));

        // 3. SBOM AI 생성 제외(Java 백엔드 자동 부록 첨부) 지침 검증
        assertTrue(prompt.contains("의존성 목록(SBOM)은 AI 생성 제외 (Java 백엔드 자동 부록 첨부)"));

        // 4. 줄글 작성 금지 및 Bullet points 구조화 지침 검증
        assertTrue(prompt.contains("줄글 문단 엄격 금지"));
        assertTrue(prompt.contains("- **[취약점 종류]** `발생 위치`: 구체적인 위협 설명 1줄"));

        // 5. 각 토글 내부 조치 가이드 및 코드 Diff 개행 규칙 검증
        assertTrue(prompt.contains("토글 내 조치 가이드 및 코드 Diff 개행 규칙"));
        assertTrue(prompt.contains("**(패치 명령어)**"));
        assertTrue(prompt.contains("```bash\nnpm install ..."));
        assertTrue(prompt.contains("**(수정 제안 코드)**"));
        assertTrue(prompt.contains("```diff"));
        assertTrue(prompt.contains("- // ❌ 기존 취약한 코드"));
        assertTrue(prompt.contains("+ // ✅ 안전하게 수정된 코드"));
    }

    @Test
    @DisplayName("커스텀 보안 정책(.prguard.yml)에 지정된 무시 패키지 및 심각도는 스캔 요약 집계에서 제외되어야 한다")
    void shouldFilterVulnerabilitiesAccordingToCustomConfig() {
        String trivyJson = """
                {
                  "SchemaVersion": 2,
                  "Results": [
                    {
                      "Target": "package-lock.json",
                      "Class": "lang-pkgs",
                      "Vulnerabilities": [
                        {
                          "VulnerabilityID": "CVE-2021-1111",
                          "PkgName": "lodash",
                          "Severity": "HIGH",
                          "Title": "Lodash Prototype Pollution"
                        },
                        {
                          "VulnerabilityID": "CVE-2022-2222",
                          "PkgName": "debug",
                          "Severity": "LOW",
                          "Title": "Debug ReDoS"
                        },
                        {
                          "VulnerabilityID": "CVE-2023-3333",
                          "PkgName": "axios",
                          "Severity": "CRITICAL",
                          "Title": "Axios SSRF"
                        }
                      ],
                      "Packages": [
                        { "Name": "lodash", "Version": "4.17.20", "Indirect": false },
                        { "Name": "debug", "Version": "2.6.9", "Indirect": true },
                        { "Name": "axios", "Version": "0.21.1", "Indirect": false }
                      ]
                    }
                  ]
                }
                """;

        // lodash 패키지 무시, LOW 심각도 무시
        io.github.hanjungho.prguard.dto.PrguardConfig config = new io.github.hanjungho.prguard.dto.PrguardConfig(
                List.of("LOW"),
                List.of("lodash"),
                List.of(),
                List.of("CRITICAL")
        );

        LLMAnalysisService.ScanSummaryPayload summary = service.extractScanSummary(trivyJson, config);

        assertNotNull(summary);
        // axios (CRITICAL) 1건만 남아야 함
        assertEquals(1, summary.totalVulnerabilitiesCount(), "lodash(HIGH)와 debug(LOW)는 무시되어 axios 1건만 남아야 함");
        assertEquals("axios", summary.topVulnerabilities().get(0).pkgName());
        assertEquals("CRITICAL", summary.topVulnerabilities().get(0).severity());
    }

    @Test
    @DisplayName("보안 위험이 0건이고 Diff가 비어있는 경우(문서/스타일만 수정된 PR) Short-Circuit PASS가 즉시 반환되어야 한다")
    void shouldShortCircuitPassWhenZeroFindingsAndEmptyDiff() {
        String trivyJson = """
                {
                  "SchemaVersion": 2,
                  "Results": [
                    {
                      "Target": "Dockerfile",
                      "Class": "config",
                      "Misconfigurations": []
                    }
                  ]
                }
                """;

        // diff가 비어있음 (문서/스타일 파일 필터링 후 빈 diff)
        LLMAnalysisService.AnalysisOutcome outcome = service.analyzeVulnerabilities(
                trivyJson, "", "", io.github.hanjungho.prguard.dto.PrguardConfig.defaultConfig());

        assertNotNull(outcome);
        assertEquals(LLMAnalysisService.SecurityVerdict.PASS, outcome.verdict());
        assertTrue(outcome.reportMarkdown().contains("승인 (PASS)"));
    }

    @Test
    @DisplayName("동일한 컨텍스트로 2회 호출 시 SHA-256 메모이제이션 캐시가 적중하여 동일 객체가 즉시 반환되어야 한다")
    void shouldReturnCachedOutcomeOnIdenticalInputs() {
        String trivyJson = """
                {
                  "SchemaVersion": 2,
                  "Results": [
                    {
                      "Target": "Dockerfile",
                      "Class": "config",
                      "Misconfigurations": []
                    }
                  ]
                }
                """;

        LLMAnalysisService.AnalysisOutcome outcome1 = service.analyzeVulnerabilities(
                trivyJson, "", "node: 18", io.github.hanjungho.prguard.dto.PrguardConfig.defaultConfig());
        LLMAnalysisService.AnalysisOutcome outcome2 = service.analyzeVulnerabilities(
                trivyJson, "", "node: 18", io.github.hanjungho.prguard.dto.PrguardConfig.defaultConfig());

        assertNotNull(outcome1);
        assertNotNull(outcome2);
        assertSame(outcome1, outcome2, "동일 입력 시 캐시된 결과 객체가 반환되어야 함");
    }

    @Test
    @DisplayName("Trivy의 Lockfile 결과에 Indirect 여부가 없더라도 manifestPackages의 정확한 간접 의존성 분류가 우선 적용되어야 한다")
    void shouldMergeManifestPackagesPreservingIndirectClassification() {
        String trivyJson = """
                {
                  "SchemaVersion": 2,
                  "Results": [
                    {
                      "Target": "gradle.lockfile",
                      "Class": "lang-pkgs",
                      "Type": "gradle",
                      "Packages": [
                        {
                          "Name": "org.springframework.boot:spring-boot-starter-webmvc",
                          "Version": "4.1.2",
                          "Indirect": false
                        },
                        {
                          "Name": "org.apache.tomcat.embed:tomcat-embed-core",
                          "Version": "11.0.27",
                          "Indirect": false
                        }
                      ]
                    }
                  ]
                }
                """;

        List<LLMAnalysisService.SbomPackageDetail> manifestPackages = List.of(
                new LLMAnalysisService.SbomPackageDetail("org.springframework.boot:spring-boot-starter-webmvc", "4.1.2", false, "Maven/Gradle"),
                new LLMAnalysisService.SbomPackageDetail("org.apache.tomcat.embed:tomcat-embed-core", "11.0.27", true, "Maven/Gradle")
        );

        LLMAnalysisService.AnalysisOutcome outcome = service.analyzeVulnerabilities(
                trivyJson, "", "", io.github.hanjungho.prguard.dto.PrguardConfig.defaultConfig(), manifestPackages);

        assertNotNull(outcome);
        LLMAnalysisService.ScanSummaryPayload summary = outcome.summaryPayload();
        assertEquals(2, summary.sbomStats().totalCount());
        assertEquals(1, summary.sbomStats().directCount(), "직접 의존성은 1개여야 함");
        assertEquals(1, summary.sbomStats().transitiveCount(), "간접 의존성은 1개로 정확히 갱신되어야 함");
    }

    @Test
    @DisplayName("Gemini API가 503 등으로 일시 불능일 때도 Trivy 전수 검사 데이터를 기반으로 파이프라인 중단 없이 자가 복구 리포트를 생성해야 한다")
    void shouldGenerateFallbackDeterministicReportWhenLlmUnavailable() {
        LLMAnalysisService.ScanSummaryPayload payload = new LLMAnalysisService.ScanSummaryPayload(
                new LLMAnalysisService.SbomStats(1, 1, 0),
                List.of(new LLMAnalysisService.SbomPackageDetail("lodash", "4.17.21", false, "MIT")),
                new LLMAnalysisService.VulnStats(0, 0, 0, 0, 0),
                List.of(),
                0,
                List.of(),
                0,
                List.of(),
                0
        );

        String report = service.buildFallbackDeterministicReport(payload, io.github.hanjungho.prguard.dto.PrguardConfig.defaultConfig());

        assertNotNull(report);
        assertTrue(report.contains("승인 (PASS)"));
        assertTrue(report.contains("오픈소스 취약점 (CVE):** 총 0건 (안전)"));
        assertTrue(report.contains("Google 503"));
    }
}

