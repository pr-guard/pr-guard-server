package io.github.hanjungho.prguard.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * OWASP CycloneDX v1.5 표준 규격을 완벽히 준수하는 기계 판독형 SBOM(Software Bill of Materials) 엔진.
 * 미국 백악관 행정명령(EO 14028) 및 NTIA Minimum Elements for SBOM 규격에 따라
 * 고유 PURL(Package URL), SPDX 라이선스, SHA-256 무결성 해시, 프로젝트 환경 메타데이터 및
 * 직접/간접(전이) 의존성 관계 트리, 외부 SaaS 연동 서비스를 국제 표준 JSON 형식으로 생성하고 REST API로 제공합니다.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class CycloneDxSbomService {

    private final ObjectMapper objectMapper;

    private static final int MAX_CACHE_SIZE = 200;

    /**
     * 외부 SaaS 연동 서비스 상세 레코드 (CycloneDX 1.5 'services' 컴포넌트 대응)
     */
    public record ExternalServiceDetail(
            String name,
            String provider,
            String endpoint,
            String dataClassification
    ) {}

    /**
     * 최근 생성된 CycloneDX SBOM JSON 메모이제이션 캐시 (REST API 조회용)
     * Key: "owner/repo#prNumber", Value: CycloneDX JSON 문자열
     */
    private final Map<String, String> sbomCache = Collections.synchronizedMap(
            new LinkedHashMap<>(64, 0.75f, true) {
                @Override
                protected boolean removeEldestEntry(Map.Entry<String, String> eldest) {
                    return size() > MAX_CACHE_SIZE;
                }
            }
    );

    /**
     * 패키지명, 설치 버전 및 생태계 힌트를 기반으로 글로벌 표준 Package URL (purl) 식별자를 생성합니다.
     * 규격: RFC / Package URL Specification (https://github.com/package-url/purl-spec)
     */
    public static String generatePurl(String name, String version, String ecosystemHint) {
        if (name == null || name.isBlank()) {
            return "";
        }

        String safeVersion = (version != null && !version.isBlank() && !"(managed)".equals(version) && !"BOM-managed".equals(version))
                ? version.trim()
                : "unknown";

        String trimmedName = name.trim();
        if (trimmedName.startsWith("pkg:")) {
            return trimmedName;
        }

        String hint = (ecosystemHint != null) ? ecosystemHint.toLowerCase() : "";

        // 1. Maven / Gradle (group:artifact 형태)
        if (trimmedName.contains(":") && (hint.contains("maven") || hint.contains("gradle") || !hint.contains("npm"))) {
            String[] parts = trimmedName.split(":", 2);
            String group = parts[0].trim();
            String artifact = parts[1].trim();
            return String.format("pkg:maven/%s/%s@%s", group, artifact, safeVersion);
        }

        // 2. npm / Node.js
        if (hint.contains("npm") || hint.contains("node") || hint.contains("yarn") || hint.contains("pnpm") || trimmedName.startsWith("@")) {
            if (trimmedName.startsWith("@") && trimmedName.contains("/")) {
                String[] parts = trimmedName.split("/", 2);
                String scope = URLEncoder.encode(parts[0], StandardCharsets.UTF_8);
                String pkg = parts[1];
                return String.format("pkg:npm/%s/%s@%s", scope, pkg, safeVersion);
            }
            return String.format("pkg:npm/%s@%s", trimmedName, safeVersion);
        }

        // 3. PyPI (Python)
        if (hint.contains("pypi") || hint.contains("python") || hint.contains("pip") || hint.contains("poetry")) {
            return String.format("pkg:pypi/%s@%s", trimmedName.toLowerCase(), safeVersion);
        }

        // 4. Cargo (Rust)
        if (hint.contains("cargo") || hint.contains("rust") || hint.contains("crates")) {
            return String.format("pkg:cargo/%s@%s", trimmedName, safeVersion);
        }

        // 5. Go (Golang)
        if (hint.contains("go") || hint.contains("golang") || trimmedName.startsWith("github.com/") || trimmedName.startsWith("golang.org/")) {
            return String.format("pkg:golang/%s@%s", trimmedName, safeVersion);
        }

        // 6. NuGet (C# / .NET)
        if (hint.contains("nuget") || hint.contains(".net") || hint.contains("csharp")) {
            return String.format("pkg:nuget/%s@%s", trimmedName, safeVersion);
        }

        // 7. CocoaPods / Swift (iOS / macOS)
        if (hint.contains("cocoapods") || hint.contains("swift") || hint.contains("pod")) {
            return String.format("pkg:cocoapods/%s@%s", trimmedName, safeVersion);
        }

        // 8. Pub (Dart / Flutter)
        if (hint.contains("pub") || hint.contains("flutter") || hint.contains("dart")) {
            return String.format("pkg:pub/%s@%s", trimmedName, safeVersion);
        }

        // 9. Composer (PHP)
        if (hint.contains("composer") || hint.contains("php")) {
            return String.format("pkg:composer/%s@%s", trimmedName, safeVersion);
        }

        // 10. 기타 범용 패키지
        return String.format("pkg:generic/%s@%s", trimmedName, safeVersion);
    }

    /**
     * 저장소 내 실제 코드 및 설정 파일(application.properties, .env, Dockerfile 등)을 정밀 스캔하여
     * 통신 중인 외부 SaaS 및 타사 서비스 엔드포인트를 자동 감지합니다.
     */
    public List<ExternalServiceDetail> detectExternalServices(Path rootDir) {
        if (rootDir == null || !Files.exists(rootDir)) {
            return Collections.emptyList();
        }

        Map<String, ExternalServiceDetail> detected = new LinkedHashMap<>();

        try {
            Files.walkFileTree(rootDir, new SimpleFileVisitor<>() {
                private int scannedFiles = 0;

                @Override
                public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) {
                    String name = dir.getFileName() != null ? dir.getFileName().toString() : "";
                    if (name.startsWith(".") || name.equals("node_modules") || name.equals("build")
                            || name.equals("target") || name.equals(".git") || name.equals("gradle")) {
                        if (!name.equals(".")) return FileVisitResult.SKIP_SUBTREE;
                    }
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                    if (++scannedFiles > 200) {
                        return FileVisitResult.TERMINATE;
                    }
                    String lower = file.getFileName().toString().toLowerCase();
                    if (lower.endsWith(".properties") || lower.endsWith(".yml") || lower.endsWith(".yaml")
                            || lower.endsWith(".json") || lower.endsWith(".java") || lower.endsWith(".ts")
                            || lower.endsWith(".js") || lower.endsWith(".py") || lower.endsWith(".go")
                            || lower.endsWith(".cs") || lower.equals(".env") || lower.startsWith(".env.")) {
                        try {
                            String content = Files.readString(file, StandardCharsets.UTF_8);
                            checkContentForServices(content, detected);
                        } catch (Exception ignored) {}
                    }
                    return FileVisitResult.CONTINUE;
                }
            });
        } catch (Exception e) {
            log.debug("[CycloneDx] 외부 서비스 탐색 중 경고: {}", e.getMessage());
        }

        return new ArrayList<>(detected.values());
    }

    private void checkContentForServices(String content, Map<String, ExternalServiceDetail> map) {
        if (content.contains("generativelanguage.googleapis.com") || (content.contains("gemini") && content.contains("api.url"))) {
            map.putIfAbsent("Google Gemini AI", new ExternalServiceDetail(
                    "Google Gemini AI", "Google Cloud", "https://generativelanguage.googleapis.com", "AI 코드 분석 및 보안 진단 (민감 토큰 마스킹)"));
        }
        if (content.contains("api.github.com") || content.contains("github.com/api")) {
            map.putIfAbsent("GitHub API", new ExternalServiceDetail(
                    "GitHub REST & Checks API", "GitHub / Microsoft", "https://api.github.com", "Check Run 상태 동기화 및 PR 코멘트 등록"));
        }
        if (content.contains("api.openai.com")) {
            map.putIfAbsent("OpenAI API", new ExternalServiceDetail(
                    "OpenAI API", "OpenAI", "https://api.openai.com", "LLM 인퍼런스 프롬프트 및 완성 데이터"));
        }
        if (content.contains("api.tosspayments.com") || content.contains("tosspayments")) {
            map.putIfAbsent("Toss Payments", new ExternalServiceDetail(
                    "Toss Payments", "비바리퍼블리카", "https://api.tosspayments.com", "전자결제 주문 및 결제 승인 데이터 (PCI-DSS)"));
        }
        if (content.contains("api.stripe.com")) {
            map.putIfAbsent("Stripe", new ExternalServiceDetail(
                    "Stripe Payments", "Stripe", "https://api.stripe.com", "결제 트랜잭션 및 인증 토큰"));
        }
        if (content.contains("kapi.kakao.com")) {
            map.putIfAbsent("Kakao API", new ExternalServiceDetail(
                    "Kakao API", "카카오", "https://kapi.kakao.com", "사용자 계정 인증 및 소셜 연동"));
        }
        if (content.contains(".amazonaws.com")) {
            map.putIfAbsent("AWS", new ExternalServiceDetail(
                    "Amazon Web Services (AWS)", "Amazon", "https://*.amazonaws.com", "클라우드 스토리지 / 백엔드 인프라 자원"));
        }
        if (content.contains("firebaseio.com") || content.contains("firestore.googleapis.com")) {
            map.putIfAbsent("Firebase", new ExternalServiceDetail(
                    "Firebase", "Google Cloud", "https://*.firebaseio.com", "실시간 데이터베이스 및 푸시 알림"));
        }
        if (content.contains(".ingest.sentry.io") || content.contains("sentry.io")) {
            map.putIfAbsent("Sentry", new ExternalServiceDetail(
                    "Sentry Error Tracking", "Functional Software", "https://*.ingest.sentry.io", "애플리케이션 런타임 에러 스택 트레이스"));
        }
        if (content.contains("hooks.slack.com")) {
            map.putIfAbsent("Slack", new ExternalServiceDetail(
                    "Slack Webhook", "Salesforce", "https://hooks.slack.com", "CI/CD 빌드 알림 메시지"));
        }
    }

    public String buildCycloneDxJson(
            String repoFullName,
            Integer prNumber,
            String projectEnvironment,
            List<LLMAnalysisService.SbomPackageDetail> packages,
            List<LLMAnalysisService.VulnerabilityDetail> vulnerabilities
    ) {
        return buildCycloneDxJson(repoFullName, prNumber, projectEnvironment, packages, vulnerabilities, Collections.emptyList());
    }

    /**
     * 수집된 패키지, 외부 SaaS 서비스 및 취약점 정보를 바탕으로 CycloneDX v1.5 JSON 규격의 SBOM을 동적으로 생성합니다.
     */
    public String buildCycloneDxJson(
            String repoFullName,
            Integer prNumber,
            String projectEnvironment,
            List<LLMAnalysisService.SbomPackageDetail> packages,
            List<LLMAnalysisService.VulnerabilityDetail> vulnerabilities,
            List<ExternalServiceDetail> externalServices
    ) {
        ObjectNode root = objectMapper.createObjectNode();

        // 1. CycloneDX v1.5 Header
        root.put("$schema", "http://cyclonedx.org/schema/bom-1.5.schema.json");
        root.put("bomFormat", "CycloneDX");
        root.put("specVersion", "1.5");
        String serialNumber = "urn:uuid:" + UUID.randomUUID();
        root.put("serialNumber", serialNumber);
        root.put("version", 1);

        // 2. Metadata (작성 도구, 생성 일시, 대상 프로젝트 환경 및 빌드 도구)
        ObjectNode metadata = root.putObject("metadata");
        metadata.put("timestamp", DateTimeFormatter.ISO_INSTANT.format(Instant.now()));

        ArrayNode tools = metadata.putArray("tools");
        ObjectNode tool = tools.addObject();
        tool.put("vendor", "PR Guard");
        tool.put("name", "pr-guard-sbom-engine");
        tool.put("version", "1.0.0");

        ObjectNode appComponent = metadata.putObject("component");
        appComponent.put("type", "application");
        appComponent.put("name", (repoFullName != null && !repoFullName.isBlank()) ? repoFullName : "pr-guard-target-app");
        if (prNumber != null) {
            appComponent.put("version", "PR #" + prNumber);
        }

        ArrayNode metaProperties = appComponent.putArray("properties");
        if (projectEnvironment != null && !projectEnvironment.isBlank()) {
            ObjectNode envProp = metaProperties.addObject();
            envProp.put("name", "prguard:project:environment");
            envProp.put("value", projectEnvironment);
        }

        // 3. Components (직접/간접 의존성 목록 전수 등록)
        ArrayNode components = root.putArray("components");
        ArrayNode dependencies = root.putArray("dependencies");

        ArrayNode rootDependsOn = null;
        ObjectNode rootDepNode = null;
        if (repoFullName != null && !repoFullName.isBlank()) {
            rootDepNode = dependencies.addObject();
            rootDepNode.put("ref", repoFullName);
            rootDependsOn = rootDepNode.putArray("dependsOn");
        }

        if (packages != null) {
            for (LLMAnalysisService.SbomPackageDetail pkg : packages) {
                ObjectNode comp = components.addObject();
                comp.put("type", "library");

                String purl = (pkg.purl() != null && !pkg.purl().isBlank() && !pkg.purl().startsWith("pkg:generic/"))
                        ? pkg.purl()
                        : generatePurl(pkg.name(), pkg.version(), (projectEnvironment != null && !projectEnvironment.isBlank()) ? projectEnvironment : pkg.license());

                comp.put("bom-ref", purl);
                comp.put("name", pkg.name());

                String ver = (pkg.version() != null && !pkg.version().isBlank() && !"(managed)".equals(pkg.version()) && !"BOM-managed".equals(pkg.version()))
                        ? pkg.version()
                        : "unknown";
                comp.put("version", ver);
                comp.put("purl", purl);
                comp.put("scope", pkg.indirect() ? "optional" : "required");

                // 라이선스 정보
                if (pkg.license() != null && !"-".equals(pkg.license()) && !pkg.license().isBlank()) {
                    ArrayNode licensesArr = comp.putArray("licenses");
                    ObjectNode licNode = licensesArr.addObject();
                    ObjectNode licInner = licNode.putObject("license");
                    licInner.put("id", pkg.license());
                }

                // 의존성 속성 메타데이터 (직접/간접 구분 및 에코시스템)
                ArrayNode compProperties = comp.putArray("properties");
                ObjectNode typeProp = compProperties.addObject();
                typeProp.put("name", "prguard:dependency:type");
                typeProp.put("value", pkg.indirect() ? "transitive" : "direct");

                // 최상위 애플리케이션의 직접 의존성 관계 트리 등록
                if (!pkg.indirect() && rootDependsOn != null) {
                    rootDependsOn.add(purl);
                }
            }
        }

        // 4. Services (외부 연동 SaaS / API 자산 등록 - CycloneDX 1.5 규격)
        if (externalServices != null && !externalServices.isEmpty()) {
            ArrayNode servicesArray = root.putArray("services");
            for (ExternalServiceDetail s : externalServices) {
                ObjectNode sNode = servicesArray.addObject();
                sNode.put("bom-ref", "service:" + s.name().toLowerCase().replaceAll("[^a-z0-9]", "-"));
                sNode.put("name", s.name());

                ArrayNode endpoints = sNode.putArray("endpoints");
                endpoints.add(s.endpoint());

                ObjectNode provider = sNode.putObject("provider");
                provider.put("name", s.provider());

                ArrayNode data = sNode.putArray("data");
                ObjectNode dNode = data.addObject();
                dNode.put("flow", "bi-directional");
                dNode.put("classification", s.dataClassification());
            }
        }

        // 5. Vulnerabilities (검출된 취약점이 있을 경우 CycloneDX VEX 형태로 연계)
        if (vulnerabilities != null && !vulnerabilities.isEmpty()) {
            ArrayNode vulnsArray = root.putArray("vulnerabilities");
            for (LLMAnalysisService.VulnerabilityDetail vuln : vulnerabilities) {
                ObjectNode vulnNode = vulnsArray.addObject();
                vulnNode.put("id", vuln.vulnerabilityId());

                ObjectNode source = vulnNode.putObject("source");
                source.put("name", "NVD");
                source.put("url", "https://nvd.nist.gov/vuln/detail/" + vuln.vulnerabilityId());

                ArrayNode ratings = vulnNode.putArray("ratings");
                ObjectNode rating = ratings.addObject();
                rating.put("severity", vuln.severity().toLowerCase());

                if (vuln.title() != null && !vuln.title().isBlank()) {
                    vulnNode.put("description", vuln.title());
                }

                // 취약점 영향을 받는 대상 컴포넌트 purl 매핑
                ArrayNode affects = vulnNode.putArray("affects");
                ObjectNode targetAffect = affects.addObject();
                targetAffect.put("ref", generatePurl(vuln.pkgName(), vuln.installedVersion(), ""));
            }
        }

        String jsonResult;
        try {
            jsonResult = objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(root);
        } catch (Exception e) {
            log.error("[CycloneDx] CycloneDX JSON 직렬화 실패: {}", e.getMessage(), e);
            jsonResult = "{}";
        }

        // REST 조회용 캐시에 보관
        if (repoFullName != null && prNumber != null) {
            cacheSbom(repoFullName, prNumber, jsonResult);
        }

        return jsonResult;
    }

    /**
     * CycloneDX SBOM 데이터를 인간이 읽기 가장 편한 최적의 4-카테고리 마크다운 리포트로 렌더링합니다.
     * ① 런타임 및 빌드 환경 (Environment)
     * ② 오픈소스 및 패키지 의존성 (Dependencies - Direct vs Transitive)
     * ③ 외부 연동 서비스 및 SaaS 자산 (External Services)
     * ④ 무결성 원본 데이터 및 기계 판독 다운로드 링크 (Integrity & Download)
     */
    public String renderSbomMarkdownReport(
            String repoFullName,
            Integer prNumber,
            String projectEnvironment,
            String runtimeContext,
            List<LLMAnalysisService.SbomPackageDetail> packages,
            List<ExternalServiceDetail> externalServices,
            String cycloneDxJson
    ) {
        int totalPackages = (packages != null) ? packages.size() : 0;
        int totalServices = (externalServices != null) ? externalServices.size() : 0;
        int totalCount = totalPackages + totalServices;

        if (totalCount == 0) {
            return """
                    <details>
                    <summary><b>소프트웨어 자재 명세서 (SBOM) 구성 요소 보기 (등록된 외부 의존성 없음)</b></summary>

                    > **구성 요소 정보 없음:** 대상 레포지토리에 외부 의존성 매니페스트 파일 또는 패키지가 존재하지 않습니다.

                    </details>""";
        }

        List<LLMAnalysisService.SbomPackageDetail> directPackages = new ArrayList<>();
        List<LLMAnalysisService.SbomPackageDetail> indirectPackages = new ArrayList<>();

        if (packages != null) {
            for (LLMAnalysisService.SbomPackageDetail pkg : packages) {
                if (pkg.indirect()) {
                    indirectPackages.add(pkg);
                } else {
                    directPackages.add(pkg);
                }
            }
        }

        String nowIso = DateTimeFormatter.ISO_INSTANT.format(Instant.now().truncatedTo(java.time.temporal.ChronoUnit.SECONDS));
        String sha256 = (cycloneDxJson != null && !cycloneDxJson.isBlank())
                ? computeSha256(cycloneDxJson)
                : computeSha256(packages.toString());

        StringBuilder sb = new StringBuilder();
        sb.append("<details>\n");
        sb.append("<summary><b>소프트웨어 자재 명세서 (SBOM) 구성 요소 보기 (총 ").append(totalCount).append("개)</b></summary>\n\n");

        sb.append("> **소프트웨어 구성 요소:** 직접 의존성 ").append(directPackages.size()).append("개 / 간접 의존성 ").append(indirectPackages.size()).append("개");
        if (totalServices > 0) {
            sb.append(" / 외부 연동 서비스 ").append(totalServices).append("개");
        }
        sb.append("<br>\n");

        if (projectEnvironment != null && !projectEnvironment.isBlank() && !"미지정".equals(projectEnvironment) && !"미지정 (기타 프로젝트)".equals(projectEnvironment)) {
            sb.append("> **프로젝트 환경:** ").append(projectEnvironment).append("<br>\n");
        }
        sb.append("> **표준 규격:** OWASP CycloneDX v1.5 JSON (Package URL `purl` 매핑)<br>\n");
        sb.append("> **수집 정보:** PR Guard v1.0.0 (수집 일시: `").append(nowIso).append("`)<br>\n");
        sb.append(">\n");
        sb.append("> 💡 **의존성 구분 안내**<br>\n");
        sb.append("> • **직접 의존성 (Direct):** 개발자가 매니페스트에 직접 선언한 상위 라이브러리<br>\n");
        sb.append("> • **간접 의존성 (Transitive):** 런타임 종속 전이 패키지 (*공급망 취약점의 80% 이상 발생*)<br>\n\n");

        // -------------------------------------------------------------
        // 카테고리 1: 런타임 및 빌드 환경 (Environment)
        // -------------------------------------------------------------
        sb.append("---\n\n### 1. 런타임 및 빌드 환경 (Environment)\n\n");
        sb.append("| 항목 | 명칭 및 환경 정보 | 비고 |\n");
        sb.append("| :--- | :--- | :--- |\n");

        String langEnv = (projectEnvironment != null && !projectEnvironment.isBlank()) ? projectEnvironment : "표준 프로젝트";
        sb.append("| **언어 및 런타임** | `").append(extractLanguage(langEnv)).append("` | 핵심 프로그래밍 실행 환경 |\n");
        sb.append("| **빌드 도구 / 패키지 매니저** | `").append(extractBuildTool(langEnv)).append("` | 의존성 해결 및 패키징 엔진 |\n");
        sb.append("| **핵심 프레임워크** | `").append(extractFramework(langEnv)).append("` | 애플리케이션 프레임워크 |\n");

        String containerInfo = extractContainerOrCi(runtimeContext);
        sb.append("| **배포 컨테이너 / 인프라** | `").append(containerInfo).append("` | 런타임 베이스 이미지 / CI |\n\n");

        // -------------------------------------------------------------
        // 카테고리 2: 오픈소스 및 패키지 의존성 (Dependencies)
        // -------------------------------------------------------------
        sb.append("---\n\n### 2. 오픈소스 및 패키지 의존성 (Dependencies)\n\n");

        // 가. 직접 의존성 표 (Direct Dependencies)
        sb.append("#### 직접 의존성 (Direct Dependencies - ").append(directPackages.size()).append("개)\n\n");
        if (directPackages.isEmpty()) {
            sb.append("*(등록된 직접 의존성이 없습니다)*\n\n");
        } else {
            sb.append("| 패키지명 | 설치된 버전 | 라이선스 | 식별자 (PURL) |\n");
            sb.append("| :--- | :--- | :--- | :--- |\n");
            int maxRender = 200;
            int limit = Math.min(directPackages.size(), maxRender);
            for (int i = 0; i < limit; i++) {
                LLMAnalysisService.SbomPackageDetail pkg = directPackages.get(i);
                String ver = pkg.version().isBlank() ? "-" : "`" + pkg.version() + "`";
                String lic = pkg.license().isBlank() ? "-" : pkg.license();
                String resolvedPurl = (pkg.purl() != null && !pkg.purl().isBlank() && !pkg.purl().startsWith("pkg:generic/"))
                        ? pkg.purl()
                        : generatePurl(pkg.name(), pkg.version(), projectEnvironment);
                String purl = (resolvedPurl != null && !resolvedPurl.isBlank()) ? "`" + resolvedPurl + "`" : "-";
                sb.append("| `").append(pkg.name()).append("` | ").append(ver).append(" | ").append(lic).append(" | ").append(purl).append(" |\n");
            }
            if (directPackages.size() > maxRender) {
                sb.append("| ... | 외 ").append(directPackages.size() - maxRender).append("개 패키지 생략됨 | ... | ... |\n");
            }
            sb.append("\n");
        }

        // 나. 간접 전이 의존성 표 (Transitive Dependencies)
        sb.append("#### 간접 의존성 (Transitive Dependencies - ").append(indirectPackages.size()).append("개)\n\n");
        if (indirectPackages.isEmpty()) {
            sb.append("*(등록된 간접 의존성이 없습니다)*\n\n");
        } else {
            sb.append("| 패키지명 | 설치된 버전 | 라이선스 | 식별자 (PURL) |\n");
            sb.append("| :--- | :--- | :--- | :--- |\n");
            int maxRender = 200;
            int limit = Math.min(indirectPackages.size(), maxRender);
            for (int i = 0; i < limit; i++) {
                LLMAnalysisService.SbomPackageDetail pkg = indirectPackages.get(i);
                String ver = pkg.version().isBlank() ? "-" : "`" + pkg.version() + "`";
                String lic = pkg.license().isBlank() ? "-" : pkg.license();
                String resolvedPurl = (pkg.purl() != null && !pkg.purl().isBlank() && !pkg.purl().startsWith("pkg:generic/"))
                        ? pkg.purl()
                        : generatePurl(pkg.name(), pkg.version(), projectEnvironment);
                String purl = (resolvedPurl != null && !resolvedPurl.isBlank()) ? "`" + resolvedPurl + "`" : "-";
                sb.append("| `").append(pkg.name()).append("` | ").append(ver).append(" | ").append(lic).append(" | ").append(purl).append(" |\n");
            }
            if (indirectPackages.size() > maxRender) {
                sb.append("| ... | 외 ").append(indirectPackages.size() - maxRender).append("개 패키지 생략됨 | ... | ... |\n");
            }
            sb.append("\n");
        }

        // -------------------------------------------------------------
        // 카테고리 3: 외부 연동 서비스 및 SaaS 자산 (External Services)
        // -------------------------------------------------------------
        sb.append("---\n\n### 3. 외부 연동 서비스 및 SaaS 자산 (External Services)\n\n");
        if (externalServices == null || externalServices.isEmpty()) {
            sb.append("*(코드 및 설정에서 감지된 외부 SaaS 연동 서비스 없음)*\n\n");
        } else {
            sb.append("| 서비스명 | 제공자 (Provider) | 통신 엔드포인트 | 데이터 성격 / 민감도 |\n");
            sb.append("| :--- | :--- | :--- | :--- |\n");
            for (ExternalServiceDetail s : externalServices) {
                sb.append("| `").append(s.name()).append("` | ").append(s.provider()).append(" | `").append(s.endpoint()).append("` | ").append(s.dataClassification()).append(" |\n");
            }
            sb.append("\n");
        }

        // -------------------------------------------------------------
        // 카테고리 4: 무결성 검증 및 기계 판독 데이터 (Integrity & Raw Data Link)
        // -------------------------------------------------------------
        sb.append("---\n\n### 4. 무결성 원본 데이터 및 기계 판독 다운로드\n\n");
        if (repoFullName != null && prNumber != null) {
            String downloadUrl = "https://prguard.onrender.com/api/sbom/" + repoFullName + "/" + prNumber;
            sb.append("- **기계 판독용 원본 다운로드:** [📥 CycloneDX v1.5 JSON 다운로드](").append(downloadUrl).append(")\n");
            sb.append("- **SHA-256 무결성 해시:** `").append(sha256).append("`\n");
            sb.append("- **CLI 원클릭 조회:**\n");
            sb.append("  ```bash\n");
            sb.append("  curl -s ").append(downloadUrl).append(" | jq .\n");
            sb.append("  ```\n\n");
        } else {
            sb.append("- **SHA-256 무결성 해시:** `").append(sha256).append("`\n\n");
        }

        sb.append("</details>");
        return sb.toString();
    }

    private String extractLanguage(String projectEnv) {
        if (projectEnv == null || projectEnv.isBlank() || "미지정".equals(projectEnv)) {
            return "알 수 없음";
        }
        int slashIdx = projectEnv.indexOf('/');
        String first = (slashIdx > 0) ? projectEnv.substring(0, slashIdx).trim() : projectEnv.trim();
        int parenIdx = first.indexOf('(');
        return (parenIdx > 0) ? first.substring(0, parenIdx).trim() : first;
    }

    private String extractBuildTool(String projectEnv) {
        if (projectEnv == null) return "미지정";
        int start = projectEnv.indexOf('(');
        int end = projectEnv.indexOf(')');
        if (start >= 0 && end > start) {
            return projectEnv.substring(start + 1, end).trim();
        }
        return "미지정";
    }

    private String extractFramework(String projectEnv) {
        if (projectEnv == null) return "미지정";
        int slashIdx = projectEnv.indexOf('/');
        if (slashIdx > 0 && slashIdx + 1 < projectEnv.length()) {
            return projectEnv.substring(slashIdx + 1).trim();
        }
        return "미지정";
    }

    private String extractContainerOrCi(String runtimeContext) {
        if (runtimeContext == null || runtimeContext.isBlank()) {
            return "클라우드 네이티브 / Bare Metal";
        }
        for (String line : runtimeContext.split("\\r?\\n")) {
            String trimmed = line.trim();
            if (trimmed.startsWith("FROM ")) {
                return "Docker (" + trimmed.substring(5).trim() + ")";
            }
        }
        if (runtimeContext.contains("node:")) {
            return "Node Container";
        }
        return "클라우드 네이티브 / Bare Metal";
    }

    /**
     * 생성된 CycloneDX SBOM JSON을 캐시에 저장합니다.
     */
    public void cacheSbom(String repoFullName, Integer prNumber, String cycloneDxJson) {
        if (repoFullName == null || prNumber == null || cycloneDxJson == null) {
            return;
        }
        String key = cacheKey(repoFullName, prNumber);
        sbomCache.put(key, cycloneDxJson);
        log.info("[CycloneDx] CycloneDX v1.5 SBOM 캐시 등록 완료 (Key: {}, 크기: {} bytes)", key, cycloneDxJson.length());
    }

    /**
     * 저장된 CycloneDX SBOM JSON을 조회합니다 (REST 엔드포인트용).
     */
    public String getSbom(String repoFullName, Integer prNumber) {
        if (repoFullName == null || prNumber == null) {
            return null;
        }
        return sbomCache.get(cacheKey(repoFullName, prNumber));
    }

    /**
     * SBOM 본문의 SHA-256 무결성 검증 해시를 생성합니다.
     */
    public static String computeSha256(String content) {
        if (content == null || content.isBlank()) {
            return "";
        }
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(content.getBytes(StandardCharsets.UTF_8));
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            return "";
        }
    }

    private String cacheKey(String repoFullName, Integer prNumber) {
        return repoFullName.toLowerCase().trim() + "#" + prNumber;
    }
}
