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
import org.springframework.web.client.RestTemplate;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

@Slf4j
@Service
@RequiredArgsConstructor
public class LLMAnalysisService {

    private final ObjectMapper objectMapper;
    private final RestTemplate restTemplate;

    @Value("${gemini.api.key:YOUR_GEMINI_API_KEY_HERE}")
    private String geminiApiKey;

    @Value("${gemini.model:gemini-3.5-flash-lite}")
    private String geminiModel;

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
        log.info("[LLMAnalysis] Trivy 원본 JSON 분석 및 경량화 시작 (커스텀 정책 적용 여부: {})",
                config != null && !config.toSummaryString().contains("예외 룰 없음"));

        // 1. .prguard.yml 예외 정책을 적용하여 취약점 및 통계 필터링 추출
        ScanSummaryPayload summaryPayload = extractScanSummary(rawTrivyJson, config);
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

        String reportText;
        SecurityVerdict verdict;

        // 3. 취약점, 설정 오류, 시크릿이 전혀 없고 PR Diff도 없는 경우 조기 반환 (PASS)
        if (!summaryPayload.hasSecurityFindings() && !hasCodeDiff) {
            log.info("[LLMAnalysis] 보안 위험 요소 및 코드 변경이 없어 승인 템플릿 반환 (PASS)");
            verdict = SecurityVerdict.PASS;
            reportText = """
                    > [!TIP]
                    > ### 승인 (PASS)
                    > 오픈소스 취약점(CVE), 런타임 환경, 설정 오류 및 코드 내 보안 위협이 발견되지 않았습니다.
                    >
                    > - **오픈소스 취약점 (CVE):** 0건 (안전)
                    > - **코드 로직 및 설정 결함:** 0건 (안전)
                    """;
        } else {
            try {
                // 4. 경량화된 요약 JSON 직렬화 (@JsonIgnore로 인해 sbomPackages는 LLM에 미전송되어 비용 절감)
                String minifiedJson = objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(summaryPayload);

                // 5. Reachability, 비즈니스 로직, 런타임/Base Image 검증 및 커스텀 정책 주입 프롬프트 생성
                String prompt = buildPrompt(minifiedJson, prDiff, runtimeContext, config);

                // 6. Google Gemini API 호출
                reportText = callGeminiApi(prompt);

                // 7. SecurityVerdict 종합 판정
                if (reportText.contains("[!CAUTION]") || hasBlockingVulnerabilities(summaryPayload, config)) {
                    verdict = SecurityVerdict.BLOCK;
                } else if (reportText.contains("[!WARNING]") || summaryPayload.hasSecurityFindings()) {
                    verdict = SecurityVerdict.WARN;
                } else {
                    verdict = SecurityVerdict.PASS;
                }
            } catch (Exception e) {
                log.error("[LLMAnalysis] AI 분석 파이프라인 수행 실패: {}", e.getMessage(), e);
                throw new RuntimeException("LLM 분석 실패: " + e.getMessage(), e);
            }
        }

        // 8. AI 리포트 하단에 전체 SBOM 패키지 토글 표 Append
        String finalReport = (sbomMarkdownTable != null && !sbomMarkdownTable.isBlank())
                ? reportText.trim() + "\n\n---\n\n" + sbomMarkdownTable.trim()
                : reportText.trim();

        log.info("[LLMAnalysis] 종합 판정 완료: {}", verdict);
        return new AnalysisOutcome(finalReport, verdict, summaryPayload);
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
     * Java 단에서 직접 전체 SBOM 패키지 목록을 마크다운 표 및 <details> 태그로 렌더링합니다.
     * 직접 의존성과 간접 의존성을 2개의 독립된 표로 분리하고 라이선스 정보를 포함하여 가독성을 극대화하며,
     * LLM 토큰 비용을 0으로 유지합니다 (최대 200개 제한 안전장치 적용).
     */
    public String generateSbomMarkdownTable(List<SbomPackageDetail> packages) {
        if (packages == null || packages.isEmpty()) {
            return """
                    <details>
                    <summary><b>소프트웨어 자재 명세서 (SBOM) 구성 요소 보기 (Lock 파일 미탐지)</b></summary>

                    > **구성 요소 정보 없음:** 대상 레포지토리에 Lock 파일이 존재하지 않아 소프트웨어 자재 명세서(SBOM) 인벤토리를 탐지할 수 없습니다.

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
     * Google Gemini API 호출 (최신 모델: gemini-3.5-flash-lite / fallback: gemini-3.8-flash)
     */
    private String callGeminiApi(String prompt) {
        if (geminiApiKey == null || geminiApiKey.isBlank() || "YOUR_GEMINI_API_KEY_HERE".equals(geminiApiKey)) {
            log.warn("[LLMAnalysis] Gemini API 키가 설정되지 않았습니다. application.properties의 gemini.api.key를 설정하세요.");
            return """
                    [알림] Gemini API 키가 아직 설정되지 않았습니다.
                    src/main/resources/application.properties 파일의 'gemini.api.key' 항목에 발급받은 API 키를 입력해주세요.
                    """;
        }

        log.info("[LLMAnalysis] Google Gemini API 호출 시작 (Model: {})", geminiModel);

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

        // 1차 시도: 설정된 모델 (gemini-3.5-flash-lite)
        String primaryUrl = "https://generativelanguage.googleapis.com/v1beta/models/" + geminiModel + ":generateContent?key=" +
                    geminiApiKey;

        try {
            return requestAndParseGemini(primaryUrl, entity);
        } catch (HttpClientErrorException e) {
            log.warn("[LLMAnalysis] {} 호출 실패 ({}), gemini-3.8-flash 로 재시도합니다.", geminiModel, e.getStatusCode());
            String fallbackUrl = "https://generativelanguage.googleapis.com/v1beta/models/gemini-3.8-flash:generateContent?key=" + geminiApiKey;
            return requestAndParseGemini(fallbackUrl, entity);
        } catch (Exception e) {
            log.error("[LLMAnalysis] Gemini API 통신 중 오류 발생: {}", e.getMessage(), e);
            throw new RuntimeException("Gemini API 연동 실패: " + e.getMessage(), e);
        }
    }

    private String requestAndParseGemini(String url, HttpEntity<Map<String, Object>> entity) {
        try {
            ResponseEntity<String> response = restTemplate.postForEntity(url, entity, String.class);

            if (!response.getStatusCode().is2xxSuccessful() || response.getBody() == null) {
                throw new RuntimeException("Gemini API 호출 실패 (HTTP " + response.getStatusCode() + ")");
            }

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

        } catch (HttpClientErrorException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
