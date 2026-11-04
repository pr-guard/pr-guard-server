package io.github.hanjungho.prguard.service;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.hanjungho.prguard.dto.PrguardConfig;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.RestTemplate;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

@Slf4j
@Service
@RequiredArgsConstructor
public class LLMAnalysisService {

    private final ObjectMapper objectMapper;
    private final RestTemplate restTemplate;

    private static final int MAX_CACHE_SIZE = 500;

    /**
     * SHA-256 컨텍스트 해시 기반 AI 리포트 LRU 메모이제이션 캐시.
     * 동일 커밋 재스캔, 브랜치 단순 리베이스, PR 닫았다 열기 시 Gemini API 비용 0원 & 응답 0.001초 달성.
     */
    private final Map<String, AnalysisOutcome> reportCache = Collections.synchronizedMap(
            new LinkedHashMap<>(128, 0.75f, true) {
                @Override
                protected boolean removeEldestEntry(Map.Entry<String, AnalysisOutcome> eldest) {
                    return size() > MAX_CACHE_SIZE;
                }
            }
    );

    @Value("${gemini.api.key:YOUR_GEMINI_API_KEY_HERE}")
    private String geminiApiKey;

    @Value("${gemini.model:gemini-2.5-flash}")
    private String geminiModel;

    private static final List<String> STABLE_GEMINI_MODELS = List.of(
            "gemini-2.5-flash",
            "gemini-2.0-flash",
            "gemini-1.5-flash",
            "gemini-1.5-pro"
    );

    /**
     * SBOM 인벤토리 통계 레코드
     */
    public record SbomStats(
            int totalCount,
            int directCount,
            int transitiveCount) {
    }

    /**
     * SBOM 개별 패키지 상세 레코드 (소프트웨어 자재 명세서 렌더링용)
     */
    public record SbomPackageDetail(
            String name,
            String version,
            boolean indirect,
            String license) {

        public SbomPackageDetail(String name, String version, boolean indirect) {
            this(name, version, indirect, "-");
        }
    }

    /**
     * 취약점 등급별 건수 통계 레코드
     */
    public record VulnStats(
            int totalCount,
            int criticalCount,
            int highCount,
            int mediumCount,
            int lowCount) {
    }

    /**
     * 상세 취약점 레코드
     */
    public record VulnerabilityDetail(
            String vulnerabilityId,
            String pkgName,
            String installedVersion,
            String fixedVersion,
            String severity,
            String title) {
    }

    /**
     * 보안 설정 오류(Misconfiguration) 레코드
     */
    public record MisconfigDetail(
            String id,
            String type,
            String severity,
            String title,
            String message,
            String resolution) {
    }

    /**
     * 시크릿 노출 레코드 (원문 값은 마스킹하여 제외)
     */
    public record SecretDetail(
            String ruleId,
            String category,
            String severity,
            String title,
            int startLine) {
    }

    /**
     * 대용량 Trivy JSON을 경량화한 종합 스캔 요약 페이로드
     * (sbomPackages는 토큰 비용 절감을 위해 LLM 전송 시 @JsonIgnore로 제외)
     */
    public record ScanSummaryPayload(
            SbomStats sbomStats,
            @JsonIgnore List<SbomPackageDetail> sbomPackages,
            VulnStats vulnStats,
            List<VulnerabilityDetail> topVulnerabilities,
            int totalVulnerabilitiesCount,
            List<MisconfigDetail> misconfigurations,
            int totalMisconfigCount,
            List<SecretDetail> secrets,
            int totalSecretCount) {
        public boolean hasSecurityFindings() {
            return totalVulnerabilitiesCount > 0 || totalMisconfigCount > 0 || totalSecretCount > 0;
        }
    }

    /**
     * 하위 호환성을 위한 구 요약 레코드 (필요 시 유지)
     */
    public record VulnerabilitySummary(
            String vulnerabilityId,
            String pkgName,
            String severity,
            String title) {
    }

    /**
     * 보안 종합 판정 결과 (GitHub Checks 및 PR 라벨링과 동기화)
     */
    public enum SecurityVerdict {
        PASS, WARN, BLOCK
    }

    /**
     * AI 분석 리포트 마크다운과 보안 판정 및 요약 데이터를 포괄하는 최종 반환 레코드
     */
    public record AnalysisOutcome(
            String reportMarkdown,
            SecurityVerdict verdict,
            ScanSummaryPayload summaryPayload
    ) {}

    /**
     * 단일 인자 호출 시 (PR Diff 미제공 시) 오버로딩
     */
    public String analyzeVulnerabilities(String rawTrivyJson) {
        return analyzeVulnerabilities(rawTrivyJson, "", "", PrguardConfig.defaultConfig()).reportMarkdown();
    }

    /**
     * PR Diff만 제공 시 오버로딩
     */
    public String analyzeVulnerabilities(String rawTrivyJson, String prDiff) {
        return analyzeVulnerabilities(rawTrivyJson, prDiff, "(런타임 환경 설정 컨텍스트 없음)", PrguardConfig.defaultConfig()).reportMarkdown();
    }

    /**
     * 기본 정책(.prguard.yml 없을 때) 기반 3개 인자 오버로딩
     */
    public String analyzeVulnerabilities(String rawTrivyJson, String prDiff, String runtimeContext) {
        return analyzeVulnerabilities(rawTrivyJson, prDiff, runtimeContext, PrguardConfig.defaultConfig()).reportMarkdown();
    }

    /**
     * Trivy 원본 JSON, PR 코드 변경 내역(Diff), 프로젝트 런타임 컨텍스트, .prguard.yml 정책을 종합 분석하여
     * 리포트 마크다운과 SecurityVerdict(PASS, WARN, BLOCK)를 생성하여 반환합니다.
     */
    public AnalysisOutcome analyzeVulnerabilities(String rawTrivyJson, String prDiff, String runtimeContext, PrguardConfig config) {
        return analyzeVulnerabilities(rawTrivyJson, prDiff, runtimeContext, config, Collections.emptyList());
    }

    /**
     * 범용 매니페스트 추출 패키지(manifestPackages: C++, C#, Mobile, Game, Gradle 등)를 결합하여
     * Lock 파일 유무와 관계없이 모든 생태계의 SBOM 인벤토리를 완벽하게 복원 및 분석합니다.
     */
    public AnalysisOutcome analyzeVulnerabilities(String rawTrivyJson, String prDiff, String runtimeContext,
                                                 PrguardConfig config, List<SbomPackageDetail> manifestPackages) {
        log.info("[LLMAnalysis] 종합 보안 분석 시작 (커스텀 정책 적용 여부: {}, 범용 매니페스트 패키지: {}개)",
                config != null && !config.toSummaryString().contains("예외 룰 없음"),
                manifestPackages != null ? manifestPackages.size() : 0);

        // 1. .prguard.yml 예외 정책을 적용하여 취약점 및 통계 필터링 추출
        ScanSummaryPayload summaryPayload = extractScanSummary(rawTrivyJson, config);

        // 1-1. Trivy Lockfile 스캐너와 범용 매니페스트 스캐너 결과 통합 (C++, C#, Unity, Gradle 등 지원)
        if (manifestPackages != null && !manifestPackages.isEmpty()) {
            Map<String, SbomPackageDetail> mergedMap = new LinkedHashMap<>();
            if (summaryPayload.sbomPackages() != null) {
                for (SbomPackageDetail pkg : summaryPayload.sbomPackages()) {
                    mergedMap.put(pkg.name(), pkg);
                }
            }
            for (SbomPackageDetail pkg : manifestPackages) {
                SbomPackageDetail existing = mergedMap.get(pkg.name());
                if (existing == null) {
                    mergedMap.put(pkg.name(), pkg);
                } else {
                    String version = (existing.version() != null && !"-".equals(existing.version()) && !"(managed)".equals(existing.version()))
                            ? existing.version()
                            : pkg.version();
                    String license = (existing.license() != null && !"-".equals(existing.license()))
                            ? existing.license()
                            : pkg.license();
                    // manifestPackages의 direct/indirect 분류를 최우선 적용 (트리 기반 정확도 반영)
                    mergedMap.put(pkg.name(), new SbomPackageDetail(pkg.name(), version, pkg.indirect(), license));
                }
            }
            List<SbomPackageDetail> combinedList = new ArrayList<>(mergedMap.values());
            int direct = 0;
            int indirect = 0;
            for (SbomPackageDetail p : combinedList) {
                if (p.indirect()) indirect++;
                else direct++;
            }
            SbomStats mergedStats = new SbomStats(combinedList.size(), direct, indirect);
            summaryPayload = new ScanSummaryPayload(
                    mergedStats,
                    combinedList,
                    summaryPayload.vulnStats(),
                    summaryPayload.topVulnerabilities(),
                    summaryPayload.totalVulnerabilitiesCount(),
                    summaryPayload.misconfigurations(),
                    summaryPayload.totalMisconfigCount(),
                    summaryPayload.secrets(),
                    summaryPayload.totalSecretCount()
            );
        }

        log.info("[LLMAnalysis] 스캔 집계 결과: SBOM 총 {}개(직접 {}, 간접 {}), CVE 총 {}건(상위 {}건 선별), Misconfig {}건, Secret {}건",
                summaryPayload.sbomStats().totalCount(),
                summaryPayload.sbomStats().directCount(),
                summaryPayload.sbomStats().transitiveCount(),
                summaryPayload.totalVulnerabilitiesCount(),
                summaryPayload.topVulnerabilities().size(),
                summaryPayload.totalMisconfigCount(),
                summaryPayload.totalSecretCount());

        boolean hasCodeDiff = prDiff != null && !prDiff.isBlank() && !prDiff.contains("(PR 변경 코드 Diff가 비어 있습니다)");

        // 2. Java 단에서 직접 전체 SBOM 패키지 토글 마크다운 생성 (LLM 토큰 0 소모)
        String sbomMarkdownTable = generateSbomMarkdownTable(summaryPayload.sbomPackages());

        // ⚡ 입력 컨텍스트(요약 JSON + Diff + 런타임 + 설정) SHA-256 메모이제이션 캐시 조회
        String cacheKey = computeSha256(
                summaryPayload.toString(),
                prDiff != null ? prDiff : "",
                runtimeContext != null ? runtimeContext : "",
                config != null ? config.toSummaryString() : ""
        );

        AnalysisOutcome cached = reportCache.get(cacheKey);
        if (cached != null) {
            log.info("[LLMAnalysis] ⚡ SHA-256 컨텍스트 캐시 적중! (Key: {}...): 동일 분석 상태이므로 중복 연산 및 Gemini 호출 생략 (비용 0원 / 즉시 반환)",
                    cacheKey.substring(0, 12));
            return cached;
        }

        String reportText;
        SecurityVerdict verdict;

        // 3. 취약점, 설정 오류, 시크릿이 전혀 없고 PR Diff도 없는 경우 조기 반환 (Short-Circuit PASS)
        if (!summaryPayload.hasSecurityFindings() && !hasCodeDiff) {
            log.info("[LLMAnalysis] ⚡ 보안 위험 요소가 없고 코드 변경(Diff)이 없거나 보안 무관 파일만 수정되어 즉시 승인 (Short-Circuit PASS)");
            verdict = SecurityVerdict.PASS;
            reportText = """
                    > [!TIP]
                    > ### 승인 (PASS)
                    > 오픈소스 취약점(CVE), 런타임 환경, 설정 오류 및 코드 내 보안 위협이 발견되지 않았습니다.
                    >
                    > - **오픈소스 취약점 (CVE):** 0건 (안전)
                    > - **코드 로직 및 설정 결함:** 0건 (안전)
                    """;
            String finalReport = (sbomMarkdownTable != null && !sbomMarkdownTable.isBlank())
                    ? reportText.trim() + "\n\n---\n\n" + sbomMarkdownTable.trim()
                    : reportText.trim();

            AnalysisOutcome outcome = new AnalysisOutcome(finalReport, verdict, summaryPayload);
            reportCache.put(cacheKey, outcome);
            return outcome;
        } else {
            try {
                // 4. 경량화된 요약 JSON 직렬화 (@JsonIgnore로 인해 sbomPackages는 LLM에 미전송되어 비용 절감)
                String minifiedJson = objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(summaryPayload);

                // 5. Reachability, 비즈니스 로직, 런타임/Base Image 검증 및 커스텀 정책 주입 프롬프트 생성
                String prompt = buildPrompt(minifiedJson, prDiff, runtimeContext, config);

                // 6. Google Gemini API 호출 (일시적 503/429 장애 시 지수 백오프 및 다중 모델 Fallback 후 자가 복구 리포트 생성)
                try {
                    reportText = callGeminiApi(prompt);
                } catch (Exception llmEx) {
                    log.warn("[LLMAnalysis] ⚠️ 모든 Gemini 모델 호출 일시 장애 발생({}). Trivy 정적 전수 검사 결과 기반으로 자가 복구 리포트를 생성합니다.", llmEx.getMessage());
                    reportText = buildFallbackDeterministicReport(summaryPayload, config);
                }

                // 7. SecurityVerdict 종합 판정
                if (reportText.contains("[!CAUTION]") || hasBlockingVulnerabilities(summaryPayload, config)) {
                    verdict = SecurityVerdict.BLOCK;
                } else if (reportText.contains("[!WARNING]") || summaryPayload.hasSecurityFindings()) {
                    verdict = SecurityVerdict.WARN;
                } else {
                    verdict = SecurityVerdict.PASS;
                }

                // 8. AI 리포트 하단에 전체 SBOM 패키지 토글 표 Append
                String finalReport = (sbomMarkdownTable != null && !sbomMarkdownTable.isBlank())
                        ? reportText.trim() + "\n\n---\n\n" + sbomMarkdownTable.trim()
                        : reportText.trim();

                AnalysisOutcome outcome = new AnalysisOutcome(finalReport, verdict, summaryPayload);
                reportCache.put(cacheKey, outcome);
                log.info("[LLMAnalysis] 종합 판정 완료 및 신규 캐시 등록 (Key: {}...): {}", cacheKey.substring(0, 12), verdict);
                return outcome;

            } catch (Exception e) {
                log.error("[LLMAnalysis] AI 분석 파이프라인 수행 실패: {}", e.getMessage(), e);
                throw new RuntimeException("LLM 분석 실패: " + e.getMessage(), e);
            }
        }
    }

    private boolean hasBlockingVulnerabilities(ScanSummaryPayload payload, PrguardConfig config) {
        if (payload == null || payload.topVulnerabilities() == null || config == null) {
            return false;
        }
        for (VulnerabilityDetail vuln : payload.topVulnerabilities()) {
            if (config.shouldBlock(vuln.severity())) {
                return true;
            }
        }
        return false;
    }

    /**
     * 입력 문자열들의 SHA-256 해시를 계산하여 고유한 캐시 키를 생성합니다.
     */
    private String computeSha256(String... inputs) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            for (String input : inputs) {
                if (input != null) {
                    digest.update(input.getBytes(StandardCharsets.UTF_8));
                }
            }
            byte[] hash = digest.digest();
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            return String.valueOf(Objects.hash((Object[]) inputs));
        }
    }

    /**
     * Java 단에서 직접 전체 SBOM 패키지 목록을 마크다운 표 및 <details> 태그로 렌더링합니다.
     * 직접 의존성과 간접 의존성을 2개의 독립된 표로 분리하고 라이선스 정보를 포함하여 가독성을 극대화하며,
     * LLM 토큰 비용을 0으로 유지합니다 (최대 200개 제한 안전장치 적용).
     */
    public String generateSbomMarkdownTable(List<SbomPackageDetail> packages) {
        if (packages == null || packages.isEmpty()) {
            return """
                    <details>
                    <summary><b>소프트웨어 자재 명세서 (SBOM) 구성 요소 보기 (등록된 외부 의존성 없음)</b></summary>

                    > **구성 요소 정보 없음:** 대상 레포지토리에 외부 의존성 매니페스트 파일(build.gradle, .csproj, CMakeLists.txt, Podfile, pubspec.yaml, package.json 등) 또는 패키지가 존재하지 않습니다.

                    </details>""";
        }

        List<SbomPackageDetail> directPackages = new ArrayList<>();
        List<SbomPackageDetail> indirectPackages = new ArrayList<>();

        for (SbomPackageDetail pkg : packages) {
            if (pkg.indirect()) {
                indirectPackages.add(pkg);
            } else {
                directPackages.add(pkg);
            }
        }

        int totalCount = packages.size();
        int directCount = directPackages.size();
        int indirectCount = indirectPackages.size();
        int maxRender = 200;

        StringBuilder sb = new StringBuilder();
        sb.append("<details>\n");
        sb.append("<summary><b>소프트웨어 자재 명세서 (SBOM) 구성 요소 보기 (총 ").append(totalCount).append("개)</b></summary>\n\n");
        sb.append("> **소프트웨어 구성 요소:** 직접 의존성 ").append(directCount).append("개 / 간접 의존성 ").append(indirectCount).append("개\n\n");

        // 1. 직접 의존성 표 (Direct Dependencies)
        sb.append("#### 직접 의존성 (Direct Dependencies - ").append(directCount).append("개)\n\n");
        if (directPackages.isEmpty()) {
            sb.append("*(등록된 직접 의존성이 없습니다)*\n\n");
        } else {
            sb.append("| 패키지명 | 설치된 버전 | 라이선스 |\n");
            sb.append("| :--- | :--- | :--- |\n");
            int directLimit = Math.min(directPackages.size(), maxRender);
            for (int i = 0; i < directLimit; i++) {
                SbomPackageDetail pkg = directPackages.get(i);
                String versionDisplay = pkg.version().isBlank() ? "-" : "`" + pkg.version() + "`";
                String licenseDisplay = pkg.license().isBlank() ? "-" : pkg.license();
                sb.append("| `").append(pkg.name()).append("` | ").append(versionDisplay).append(" | ").append(licenseDisplay).append(" |\n");
            }
            if (directPackages.size() > maxRender) {
                sb.append("| ... | 외 ").append(directPackages.size() - maxRender).append("개 패키지 생략됨 | ... |\n");
            }
            sb.append("\n");
        }

        // 2. 간접 의존성 표 (Transitive Dependencies)
        sb.append("#### 간접 의존성 (Transitive Dependencies - ").append(indirectCount).append("개)\n\n");
        if (indirectPackages.isEmpty()) {
            sb.append("*(등록된 간접 의존성이 없습니다)*\n\n");
        } else {
            sb.append("| 패키지명 | 설치된 버전 | 라이선스 |\n");
            sb.append("| :--- | :--- | :--- |\n");
            int indirectLimit = Math.min(indirectPackages.size(), maxRender);
            for (int i = 0; i < indirectLimit; i++) {
                SbomPackageDetail pkg = indirectPackages.get(i);
                String versionDisplay = pkg.version().isBlank() ? "-" : "`" + pkg.version() + "`";
                String licenseDisplay = pkg.license().isBlank() ? "-" : pkg.license();
                sb.append("| `").append(pkg.name()).append("` | ").append(versionDisplay).append(" | ").append(licenseDisplay).append(" |\n");
            }
            if (indirectPackages.size() > maxRender) {
                sb.append("| ... | 외 ").append(indirectPackages.size() - maxRender).append("개 패키지 생략됨 | ... |\n");
            }
            sb.append("\n");
        }

        sb.append("</details>");
        return sb.toString();
    }

    /**
     * Trivy JSON 트리에서 모든 Results를 순회하여 SBOM 전체 패키지, 취약점(Top 30), Misconfiguration,
     * Secret을 발라냅니다.
     * 취약점(CVE)이 0건이더라도 다중 Results 내의 모든 Packages를 완전 탐색하여 집계합니다.
     */
    public ScanSummaryPayload extractScanSummary(String rawJson) {
        return extractScanSummary(rawJson, PrguardConfig.defaultConfig());
    }

    /**
     * Trivy JSON 트리에서 모든 Results를 순회하여 SBOM 전체 패키지, 취약점(Top 30), Misconfiguration,
     * Secret을 발라냅니다. .prguard.yml 정책에 의해 무시되는 항목은 사전에 배제합니다.
     */
    public ScanSummaryPayload extractScanSummary(String rawJson, PrguardConfig config) {
        Set<String> seenPackageKeys = new HashSet<>();
        List<SbomPackageDetail> sbomPackages = new ArrayList<>();
        int[] packageCounts = new int[2]; // [0]: direct, [1]: transitive

        Map<String, VulnerabilityDetail> vulnMap = new LinkedHashMap<>();
        int criticalCount = 0, highCount = 0, mediumCount = 0, lowCount = 0;

        Map<String, MisconfigDetail> misconfigMap = new LinkedHashMap<>();
        Map<String, SecretDetail> secretMap = new LinkedHashMap<>();

        try {
            JsonNode root = objectMapper.readTree(rawJson);
            JsonNode results = root.hasNonNull("Results") ? root.path("Results") : root.path("results");

            if (results.isArray()) {
                for (JsonNode resultNode : results) {
                    // 1. SBOM Packages 수집 (다중 Results 완전 순회)
                    collectPackagesFromResultNode(resultNode, seenPackageKeys, sbomPackages, packageCounts);

                    // 2. Vulnerabilities 수집 (커스텀 룰 필터링 적용)
                    JsonNode vulnerabilities = resultNode.path("Vulnerabilities");
                    if (vulnerabilities.isArray()) {
                        for (JsonNode vulnNode : vulnerabilities) {
                            String vulnId = vulnNode.path("VulnerabilityID").asText("");
                            String pkgName = vulnNode.path("PkgName").asText("");
                            String severity = vulnNode.path("Severity").asText("UNKNOWN").toUpperCase();
                            String installedVer = vulnNode.path("InstalledVersion").asText("");
                            String fixedVer = vulnNode.path("FixedVersion").asText("");
                            String title = vulnNode.path("Title").asText("");

                            // 커스텀 예외 정책(.prguard.yml)에 해당하는 취약점은 제외
                            if (config != null && config.isVulnerabilityIgnored(vulnId, pkgName, severity)) {
                                continue;
                            }

                            String key = vulnId + ":" + pkgName;
                            if (!vulnMap.containsKey(key)) {
                                vulnMap.put(key, new VulnerabilityDetail(vulnId, pkgName, installedVer, fixedVer,
                                        severity, title));

                                switch (severity) {
                                    case "CRITICAL" -> criticalCount++;
                                    case "HIGH" -> highCount++;
                                    case "MEDIUM" -> mediumCount++;
                                    case "LOW" -> lowCount++;
                                }
                            }
                        }
                    }

                    // 3. Misconfigurations 수집
                    JsonNode misconfigs = resultNode.path("Misconfigurations");
                    if (misconfigs.isArray()) {
                        for (JsonNode misNode : misconfigs) {
                            String id = misNode.path("ID").asText("");
                            String type = misNode.path("Type").asText("");
                            String severity = misNode.path("Severity").asText("UNKNOWN").toUpperCase();
                            String title = misNode.path("Title").asText("");
                            String message = misNode.path("Message").asText("");
                            String resolution = misNode.path("Resolution").asText("");

                            String key = id + ":" + title;
                            if (!misconfigMap.containsKey(key)) {
                                misconfigMap.put(key,
                                        new MisconfigDetail(id, type, severity, title, message, resolution));
                            }
                        }
                    }

                    // 4. Secrets 수집 (실제 노출된 비밀값 Match는 마스킹 처리하여 제외)
                    JsonNode secrets = resultNode.path("Secrets");
                    if (secrets.isArray()) {
                        for (JsonNode secNode : secrets) {
                            String ruleId = secNode.path("RuleID").asText("");
                            String category = secNode.path("Category").asText("");
                            String severity = secNode.path("Severity").asText("UNKNOWN").toUpperCase();
                            String title = secNode.path("Title").asText("");
                            int startLine = secNode.path("StartLine").asInt(0);

                            String key = ruleId + ":" + title + ":" + startLine;
                            if (!secretMap.containsKey(key)) {
                                secretMap.put(key, new SecretDetail(ruleId, category, severity, title, startLine));
                            }
                        }
                    }
                }
            }

            // 5. 트리 전체 재검색 방어 로직: 만약 Results 순회 후에도 sbomPackages가 비어 있다면 JSON 전체에서 Packages
            // 탐색
            if (sbomPackages.isEmpty()) {
                List<JsonNode> allPackageArrays = root.findValues("Packages");
                if (allPackageArrays.isEmpty()) {
                    allPackageArrays = root.findValues("packages");
                }
                for (JsonNode pkgArray : allPackageArrays) {
                    if (pkgArray.isArray()) {
                        for (JsonNode pkgNode : pkgArray) {
                            parseAndAddPackage(pkgNode, seenPackageKeys, sbomPackages, packageCounts);
                        }
                    }
                }
            }

        } catch (Exception e) {
            log.error("[LLMAnalysis] JSON 파싱 및 경량화 중 오류 발생: {}", e.getMessage());
            throw new RuntimeException("Trivy JSON 파싱 실패", e);
        }

        // 취약점 심각도(CRITICAL -> HIGH -> MEDIUM -> LOW) 기준 정렬 및 상위 30건 선별
        Comparator<VulnerabilityDetail> severityComparator = (v1, v2) -> Integer
                .compare(getSeverityWeight(v2.severity()), getSeverityWeight(v1.severity()));

        List<VulnerabilityDetail> sortedVulns = vulnMap.values().stream()
                .sorted(severityComparator)
                .toList();
        List<VulnerabilityDetail> top30Vulns = sortedVulns.stream().limit(30).toList();

        List<MisconfigDetail> topMisconfigs = misconfigMap.values().stream().limit(20).toList();
        List<SecretDetail> topSecrets = secretMap.values().stream().limit(20).toList();

        SbomStats sbomStats = new SbomStats(sbomPackages.size(), packageCounts[0], packageCounts[1]);
        VulnStats vulnStats = new VulnStats(vulnMap.size(), criticalCount, highCount, mediumCount, lowCount);

        return new ScanSummaryPayload(
                sbomStats,
                sbomPackages,
                vulnStats,
                top30Vulns,
                vulnMap.size(),
                topMisconfigs,
                misconfigMap.size(),
                topSecrets,
                secretMap.size());
    }

    private void collectPackagesFromResultNode(JsonNode resultNode, Set<String> seenKeys, List<SbomPackageDetail> list,
            int[] counts) {
        JsonNode packages = resultNode.hasNonNull("Packages") ? resultNode.path("Packages")
                : resultNode.path("packages");
        if (packages.isArray()) {
            for (JsonNode pkgNode : packages) {
                parseAndAddPackage(pkgNode, seenKeys, list, counts);
            }
        }
    }

    private void parseAndAddPackage(JsonNode pkgNode, Set<String> seenKeys, List<SbomPackageDetail> list,
            int[] counts) {
        String name = extractString(pkgNode, "Name", "name", "PkgName", "pkg_name");
        String version = extractString(pkgNode, "Version", "version");

        if (name.isBlank()) {
            String id = extractString(pkgNode, "ID", "id");
            if (!id.isBlank()) {
                int atIdx = id.lastIndexOf('@');
                if (atIdx > 0) {
                    name = id.substring(0, atIdx);
                    if (version.isBlank()) {
                        version = id.substring(atIdx + 1);
                    }
                } else {
                    name = id;
                }
            }
        }

        if (!name.isBlank()) {
            String key = name + "@" + version;
            if (seenKeys.add(key)) {
                boolean indirect = extractIndirect(pkgNode);
                String license = extractLicense(pkgNode);
                list.add(new SbomPackageDetail(name, version, indirect, license));
                if (indirect) {
                    counts[1]++; // transitive
                } else {
                    counts[0]++; // direct
                }
            }
        }
    }

    private String extractLicense(JsonNode pkgNode) {
        if (pkgNode.hasNonNull("Licenses")) {
            JsonNode licArr = pkgNode.path("Licenses");
            if (licArr.isArray() && !licArr.isEmpty()) {
                List<String> list = new ArrayList<>();
                for (JsonNode item : licArr) {
                    String lic = item.asText("").trim();
                    if (!lic.isBlank()) {
                        list.add(lic);
                    }
                }
                if (!list.isEmpty()) {
                    return String.join(", ", list);
                }
            } else if (!licArr.asText("").isBlank()) {
                return licArr.asText("").trim();
            }
        }
        if (pkgNode.hasNonNull("License") && !pkgNode.path("License").asText("").isBlank()) {
            return pkgNode.path("License").asText("").trim();
        }
        return "-";
    }

    private String extractString(JsonNode node, String... fieldNames) {
        for (String fieldName : fieldNames) {
            if (node.hasNonNull(fieldName) && !node.path(fieldName).asText().isBlank()) {
                return node.path(fieldName).asText().trim();
            }
        }
        return "";
    }

    private boolean extractIndirect(JsonNode pkgNode) {
        if (pkgNode.has("Indirect")) {
            return pkgNode.path("Indirect").asBoolean(false);
        }
        if (pkgNode.has("indirect")) {
            return pkgNode.path("indirect").asBoolean(false);
        }
        if (pkgNode.has("Relationship")) {
            String rel = pkgNode.path("Relationship").asText("").toLowerCase();
            return rel.contains("indirect") || rel.contains("transitive");
        }
        return false;
    }

    private int getSeverityWeight(String severity) {
        return switch (severity.toUpperCase()) {
            case "CRITICAL" -> 4;
            case "HIGH" -> 3;
            case "MEDIUM" -> 2;
            case "LOW" -> 1;
            default -> 0;
        };
    }

    String buildPrompt(String minifiedSummaryJson, String prDiff, String runtimeContext) {
        return buildPrompt(minifiedSummaryJson, prDiff, runtimeContext, PrguardConfig.defaultConfig());
    }

    /**
     * 보안 전문 AI 시스템 프롬프트 및 마크다운 고정 템플릿 구성 (커스텀 정책 적용)
     */
    String buildPrompt(String minifiedSummaryJson, String prDiff, String runtimeContext, PrguardConfig config) {
        return """
                [System Prompt]
                너는 10년 차 수석 애플리케이션 보안 아키텍트이자 DevSecOps 코드 리뷰어다.
                제공된 [1. SBOM 및 Trivy 보안 스캔 요약 JSON], [2. PR 변경 소스코드(Diff)], [3. 프로젝트 런타임 및 환경 설정 컨텍스트], [4. 프로젝트 커스텀 보안 정책(.prguard.yml)]을 종합 분석하여 개발자가 즉시 조치할 수 있는 전문적인 보안 리포트를 작성하라.

                [절대 준수 지침]
                1. 모든 이모지(Emoji) 원칙적 배제:
                   - 제목, 본문, 섹션 헤더에 이모지(🚨, ⚠️, 📦, 방패, 신호등 등)를 절대 사용하지 마라.
                   - 단, diff 수정 코드 블록 내부의 주석(// ❌, // ✅)은 가독성을 위해 규격대로 사용하라.

                2. 시각적 위계(Visual Hierarchy) 확립 및 최상단 단일 마스터 Alert 배너 적용:
                   - 최상단 판정 배너에만 유일하게 GitHub Alert([!CAUTION], [!WARNING], [!TIP])를 1회 적용하라.
                   - 하위 1번(CVE)과 2번(코드 결함) 섹션에는 Alert 블록(> [!CAUTION] 등)을 절대 중복 사용하지 마라! (동일한 거대 Alert 박스가 연속으로 나오면 시각적 위계가 무너진다)
                   - 상태별 최상단 Alert 문법:
                     - [!TIP] (초록색): 0건, 안전, 통과
                     - [!WARNING] (노란색): MEDIUM/LOW 취약점 또는 경미한 설정 결함
                     - [!CAUTION] (빨간색): CRITICAL/HIGH 취약점, 치명적 코드 결함(RCE, SQLi, SSRF, 시크릿 노출 등)
                   - 최상단 마스터 Alert 배너 내부 구성:
                     - 판정 헤드라인: `### 차단 권고 (BLOCK)` 또는 `### 주의 (WARN)` 또는 `### 승인 (PASS)`
                     - 핵심 판정 사유 1~2줄 요약
                     - 2개 항목 퀵 체크리스트(불릿 리스트):
                       - `- **오픈소스 취약점 (CVE):** 총 N건 (CRITICAL N건, HIGH N건, ...)` 또는 `0건 (안전)`
                       - `- **코드 로직 및 설정 결함:** 총 N건 (핵심 결함 요약)` 또는 `0건 (안전)`

                3. 결함이 존재하는 섹션만 상세 표기 및 <details open> 기본 펼침:
                   - 상단 마스터 Alert 배너에 이미 CVE와 코드 결함의 총 건수가 명시되어 있으므로, 0건인 안전한 항목은 하위 세부 섹션을 생성하지 말고 과감히 생략하라.
                   - 취약점(CVE)이 1건 이상 존재하는 경우에만:
                     - `### 1. 오픈소스 취약점 (CVE) — 총 N건 (CRITICAL N건, HIGH N건, MEDIUM N건, LOW N건)` 헤더 및 `<details open>` 토글 출력
                   - 코드 결함이 1건 이상 존재하는 경우에만:
                     - `### 2. 코드 로직 및 설정 결함 — 총 N건` 헤더 및 `<details open>` 토글 출력
                   - 둘 다 0건인 안전한 경우(케이스 B):
                     - 최상단 [!TIP] 승인 배너만 출력하고 하위 빈 섹션들은 일절 생성하지 마라.

                4. 의존성 목록(SBOM)은 AI 생성 제외 (Java 백엔드 자동 부록 첨부):
                   - 소프트웨어 자재 명세서(SBOM)는 Java 백엔드 단에서 리포트 최하단에 별도 부록으로 자동 첨부된다.
                   - 따라서 AI는 SBOM 섹션이나 의존성 표를 일절 출력하지 말고, 1번 CVE와 2번 코드 결함 분석에만 집중하라.

                5. 코드 로직 및 설정 결함의 구조화된 Bullet points 작성 (줄글 문단 엄격 금지):
                   - 2번 '코드 로직 및 설정 결함'을 설명할 때 절대로 긴 문단이나 장황한 줄글을 쓰지 마라.
                   - 반드시 `- **[취약점 종류]** `발생 위치`: 구체적인 위협 설명 1줄` 형식의 리스트(-)로 명확하게 끊어서 출력하라.
                   - 예시:
                     - **[시크릿 하드코딩]** `index.js`: JWT 서명 검증 시 `pipeline-test-secret`이 평문으로 노출됨.
                     - **[SSRF 위험]** `index.js`: 검증되지 않은 외부 입력값(`targetUrl`)이 `axios.get`으로 직접 전달됨.
                     - **[런타임 Base Image 취약점]** `Dockerfile`: Node.js 18.x 구버전 베이스 이미지에 Node2Shell CVE 존재.

                6. 토글 내 조치 가이드 및 코드 Diff 개행 규칙 (줄바꿈 깨짐 엄격 방지):
                   - `<summary>...</summary>` 태그 바로 다음 줄에는 반드시 빈 줄(Blank line, 2개 연속 개행)을 넣어라. 빈 줄이 없으면 깃허브에서 요약 제목과 내용이 한 줄로 합쳐진다.
                   - `<details>` 내부에는 `[!NOTE]`, `[!TIP]` 등의 Alert 문법을 쓰지 마라 (깃허브 details 내에서는 렌더링되지 않음).
                   - 1번 CVE 토글 내부 하단: 의존성 패치 명령어(```bash ... ```)
                   - 2번 코드 결함 토글 내부 하단: GitHub Copilot Autofix 스타일의 `diff` 코드 수정안 (```diff ... ```)
                   - `diff` 코드 블록 내부의 모든 줄은 반드시 개행(\\n)으로 분리되어야 하며 절대 한 줄로 합쳐지면 안 된다:
                     - `- // ❌ 기존 취약한 코드`
                     - `- 취약 코드 줄`
                     - `+ // ✅ 안전하게 수정된 코드`
                     - `+ 수정 코드 줄`

                7. 마크다운 구분선:
                   - 각 섹션 사이에는 반드시 `---` 구분선을 삽입하라.

                [입력 데이터 1: SBOM 및 Trivy 스캔 요약 JSON]
                %s

                [입력 데이터 2: PR 변경 소스코드 (Diff)]
                %s

                [입력 데이터 3: 프로젝트 런타임 및 환경 설정 컨텍스트]
                %s

                [입력 데이터 4: 프로젝트 커스텀 보안 정책 (.prguard.yml)]
                %s

                [적용할 최종 마크다운 템플릿 규격]

                ---
                ### [케이스 A: 취약점 또는 보안 결함이 발견된 경우 (WARN 또는 BLOCK)]

                > [!CAUTION] *(위험도에 따라 [!CAUTION] 또는 [!WARNING] 선택)*
                > ### 차단 권고 (BLOCK) *(또는 ### 주의 (WARN))*
                > (핵심 판정 사유 1~2줄 요약)
                >
                > - **오픈소스 취약점 (CVE):** 총 N건 (CRITICAL N건, HIGH N건, ...)
                > - **코드 로직 및 설정 결함:** 총 N건 (핵심 결함 요약)

                ---

                ### 1. 오픈소스 취약점 (CVE) — 총 N건 (CRITICAL N건, HIGH N건, MEDIUM N건, LOW N건)

                <details open>
                <summary><b>상세 취약점 내역 및 패치 가이드 보기</b></summary>

                - **[1순위] `패키지명` (CVE-ID / 위험도: CRITICAL)**
                  - **호출 여부:** 실제 호출됨 (`파일명` 내 사용)
                  - **위협 요약:** (핵심 위협 1줄)
                  - **조치:** `구버전` -> `권장버전`

                **(패치 명령어)**
                ```bash
                npm install ...
                ```

                </details>

                ---

                ### 2. 코드 로직 및 설정 결함 — 총 N건

                <details open>
                <summary><b>상세 코드 결함 및 수정 제안 (Diff) 보기</b></summary>

                - **[결함 종류명 1]** `발생 파일명`: (위험성 1줄 요약)
                - **[결함 종류명 2]** `발생 파일명`: (위험성 1줄 요약)

                **(수정 제안 코드)**
                ```diff
                - // ❌ 기존 취약한 코드
                - const secret = "hardcoded";
                + // ✅ 안전하게 수정된 코드
                + const secret = process.env.SECRET;
                ```

                </details>

                ---
                ### [케이스 B: 취약점 및 보안 결함이 전혀 없는 안전한 경우 (PASS)]

                > [!TIP]
                > ### 승인 (PASS)
                > 오픈소스 취약점(CVE), 런타임 환경, 설정 오류 및 코드 내 보안 위협이 발견되지 않았습니다.
                >
                > - **오픈소스 취약점 (CVE):** 0건 (안전)
                > - **코드 로직 및 설정 결함:** 0건 (안전)
                """
                .formatted(
                        minifiedSummaryJson,
                        (prDiff != null && !prDiff.isBlank()) ? prDiff : "(PR 변경 코드 Diff 없음)",
                        (runtimeContext != null && !runtimeContext.isBlank()) ? runtimeContext : "(런타임 환경 설정 컨텍스트 없음)",
                        (config != null) ? config.toSummaryString() : "(기본 엔터프라이즈 정책 적용 중 - 예외 룰 없음)");
    }

    /**
     * Google Gemini API 호출 (지수 백오프 재시도 및 안정화 모델 다중 Fallback 체인 적용)
     */
    private String callGeminiApi(String prompt) {
        if (geminiApiKey == null || geminiApiKey.isBlank() || "YOUR_GEMINI_API_KEY_HERE".equals(geminiApiKey)) {
            log.warn("[LLMAnalysis] Gemini API 키가 설정되지 않았습니다. application.properties의 gemini.api.key를 설정하세요.");
            return """
                    [알림] Gemini API 키가 아직 설정되지 않았습니다.
                    src/main/resources/application.properties 파일의 'gemini.api.key' 항목에 발급받은 API 키를 입력해주세요.
                    """;
        }

        List<String> modelsToTry = new ArrayList<>();
        if (geminiModel != null && !geminiModel.isBlank()) {
            modelsToTry.add(geminiModel.trim());
        }
        for (String m : STABLE_GEMINI_MODELS) {
            if (!modelsToTry.contains(m)) {
                modelsToTry.add(m);
            }
        }

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);

        Map<String, Object> requestPayload = Map.of(
                "contents", List.of(
                        Map.of("parts", List.of(
                                Map.of("text", prompt)
                        ))
                )
        );

        HttpEntity<Map<String, Object>> entity = new HttpEntity<>(requestPayload, headers);
        Exception lastException = null;

        for (String currentModel : modelsToTry) {
            String url = "https://generativelanguage.googleapis.com/v1beta/models/" + currentModel + ":generateContent?key=" + geminiApiKey;

            // 모델당 최대 2회 시도 (503 High demand, 429 Rate limit 시 지수 백오프)
            for (int attempt = 1; attempt <= 2; attempt++) {
                try {
                    log.info("[LLMAnalysis] Google Gemini API 호출 (모델: {}, 시도: {}/2)", currentModel, attempt);
                    return requestAndParseGemini(url, entity);
                } catch (HttpStatusCodeException e) {
                    lastException = e;
                    int statusCode = e.getStatusCode().value();

                    // 503 (High demand) 또는 429 (Rate limit) 또는 500/502/504 서버 오류 시 대기 후 재시도
                    if (statusCode == 503 || statusCode == 429 || statusCode >= 500) {
                        log.warn("[LLMAnalysis] 모델 {} 일시적 장애(HTTP {}): {}. 지수 백오프 대기 후 재시도합니다.",
                                currentModel, statusCode, e.getStatusText());
                        try {
                            Thread.sleep(attempt * 1200L); // 1.2초, 2.4초 대기
                        } catch (InterruptedException ie) {
                            Thread.currentThread().interrupt();
                        }
                    } else if (statusCode == 404) {
                        log.warn("[LLMAnalysis] 모델 {}이(가) 현재 엔드포인트에 존재하지 않습니다(404). 다음 대체 모델로 즉시 전환합니다.", currentModel);
                        break;
                    } else {
                        log.warn("[LLMAnalysis] 모델 {} 호출 중 클라이언트 오류 발생(HTTP {}): {}", currentModel, statusCode, e.getMessage());
                        break;
                    }
                } catch (Exception e) {
                    lastException = e;
                    log.warn("[LLMAnalysis] 모델 {} 호출 중 네트워크/파싱 예외 발생: {}", currentModel, e.getMessage());
                    break;
                }
            }
        }

        throw new RuntimeException("모든 Gemini 모델(" + modelsToTry + ") 호출 실패: " +
                (lastException != null ? lastException.getMessage() : "상세 사유 미확인"), lastException);
    }

    private String requestAndParseGemini(String url, HttpEntity<Map<String, Object>> entity) {
        ResponseEntity<String> response = restTemplate.postForEntity(url, entity, String.class);

        if (!response.getStatusCode().is2xxSuccessful() || response.getBody() == null) {
            throw new RuntimeException("Gemini API 호출 실패 (HTTP " + response.getStatusCode() + ")");
        }

        try {
            JsonNode rootNode = objectMapper.readTree(response.getBody());
            JsonNode textNode = rootNode.path("candidates")
                    .path(0)
                    .path("content")
                    .path("parts")
                    .path(0)
                    .path("text");

            if (textNode.isMissingNode()) {
                log.warn("[LLMAnalysis] Gemini 응답 본문에서 텍스트 노드를 찾지 못했습니다: {}", response.getBody());
                return "Gemini 응답을 파싱하지 못했습니다. 원본:\n" + response.getBody();
            }

            return textNode.asText();
        } catch (Exception e) {
            throw new RuntimeException("Gemini 응답 파싱 실패", e);
        }
    }

    /**
     * Gemini API 일시 장애(503 High demand 등) 시 Trivy 정적 전수 검사 데이터를 기반으로
     * 파이프라인 중단 없이 안전하게 자동 판정하는 자가 복구 리포트 생성기.
     */
    public String buildFallbackDeterministicReport(ScanSummaryPayload payload, PrguardConfig config) {
        StringBuilder sb = new StringBuilder();

        if (hasBlockingVulnerabilities(payload, config)) {
            sb.append("> [!CAUTION]\n");
            sb.append("> ### 차단 권고 (BLOCK)\n");
            sb.append("> 심각한 보안 취약점(CRITICAL/HIGH)이 검출되어 병합이 차단되었습니다.\n>\n");
        } else if (payload.hasSecurityFindings()) {
            sb.append("> [!WARNING]\n");
            sb.append("> ### 주의 (WARN)\n");
            sb.append("> 보안 취약점 또는 주의 사항이 검출되었습니다. 내용을 검토 후 병합을 결정하세요.\n>\n");
        } else {
            sb.append("> [!TIP]\n");
            sb.append("> ### 승인 (PASS)\n");
            sb.append("> 오픈소스 취약점(CVE), 런타임 환경, 설정 오류 및 코드 내 보안 위협이 발견되지 않았습니다.\n>\n");
        }

        sb.append("> - **오픈소스 취약점 (CVE):** 총 ").append(payload.totalVulnerabilitiesCount()).append("건");
        if (payload.totalVulnerabilitiesCount() == 0) {
            sb.append(" (안전)\n");
        } else {
            sb.append(" (CRITICAL ").append(payload.vulnStats().criticalCount())
              .append("건, HIGH ").append(payload.vulnStats().highCount()).append("건)\n");
        }
        sb.append("> - **코드 로직 및 설정 결함:** 총 ").append(payload.totalMisconfigCount() + payload.totalSecretCount()).append("건");
        if ((payload.totalMisconfigCount() + payload.totalSecretCount()) == 0) {
            sb.append(" (안전)\n");
        } else {
            sb.append("\n");
        }

        sb.append("\n> [!NOTE]\n");
        sb.append("> AI 심층 분석 서비스(Gemini)가 일시적 트래픽 폭주(Google 503) 상태이므로, Trivy 정적 보안 엔진의 전수 분석 결과를 기반으로 안전하게 자동 판정되었습니다.\n");

        if (payload.totalVulnerabilitiesCount() > 0) {
            sb.append("\n---\n\n### 1. 오픈소스 취약점 (CVE) — 총 ").append(payload.totalVulnerabilitiesCount()).append("건\n\n");
            sb.append("<details open>\n<summary><b>상세 취약점 내역 보기</b></summary>\n\n");
            for (VulnerabilityDetail vuln : payload.topVulnerabilities()) {
                sb.append("- **[").append(vuln.severity()).append("] `").append(vuln.pkgName()).append("` (").append(vuln.vulnerabilityId()).append(")**\n");
                sb.append("  - **설치 버전:** `").append(vuln.installedVersion()).append("` -> **수정 버전:** `").append(vuln.fixedVersion().isBlank() ? "패치 대기" : vuln.fixedVersion()).append("`\n");
                sb.append("  - **위협 요약:** ").append(vuln.title().isBlank() ? "알려진 보안 취약점" : vuln.title()).append("\n");
            }
            sb.append("\n</details>\n");
        }

        return sb.toString();
    }
}
