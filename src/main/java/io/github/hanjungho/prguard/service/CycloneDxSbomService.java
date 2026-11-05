package io.github.hanjungho.prguard.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * OWASP CycloneDX v1.5 표준 규격을 완벽히 준수하는 기계 판독형 SBOM(Software Bill of Materials) 엔진.
 * 미국 백악관 행정명령(EO 14028) 및 NTIA Minimum Elements for SBOM 규격에 따라
 * 고유 PURL(Package URL), SPDX 라이선스, SHA-256 무결성 해시, 프로젝트 환경 메타데이터 및
 * 직접/간접(전이) 의존성 관계 트리를 국제 표준 JSON 형식으로 생성하고 REST API로 제공합니다.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class CycloneDxSbomService {

    private final ObjectMapper objectMapper;

    private static final int MAX_CACHE_SIZE = 200;

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

        String safeVersion = (version != null && !version.isBlank() && !"(managed)".equals(version))
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
     * 수집된 패키지 및 취약점 정보를 바탕으로 CycloneDX v1.5 JSON 규격의 SBOM을 동적으로 생성합니다.
     */
    public String buildCycloneDxJson(
            String repoFullName,
            Integer prNumber,
            String projectEnvironment,
            List<LLMAnalysisService.SbomPackageDetail> packages,
            List<LLMAnalysisService.VulnerabilityDetail> vulnerabilities
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

                String purl = (pkg.purl() != null && !pkg.purl().isBlank())
                        ? pkg.purl()
                        : generatePurl(pkg.name(), pkg.version(), pkg.license());

                comp.put("bom-ref", purl);
                comp.put("name", pkg.name());

                String ver = (pkg.version() != null && !pkg.version().isBlank() && !"(managed)".equals(pkg.version()))
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

        // 4. Vulnerabilities (검출된 취약점이 있을 경우 CycloneDX VEX 형태로 연계)
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
