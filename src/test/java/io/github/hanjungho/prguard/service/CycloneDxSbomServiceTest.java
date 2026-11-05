package io.github.hanjungho.prguard.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class CycloneDxSbomServiceTest {

    private CycloneDxSbomService service;
    private ObjectMapper objectMapper;

    @BeforeEach
    void setUp() {
        objectMapper = new ObjectMapper();
        service = new CycloneDxSbomService(objectMapper);
    }

    @Test
    @DisplayName("생태계별 PURL(Package URL)이 RFC 표준 규격에 맞게 정확히 생성되어야 한다")
    void shouldGenerateCorrectPurlForDifferentEcosystems() {
        // Maven / Gradle
        assertEquals("pkg:maven/org.springframework.boot/spring-boot-starter-webmvc@4.1.2",
                CycloneDxSbomService.generatePurl("org.springframework.boot:spring-boot-starter-webmvc", "4.1.2", "Maven/Gradle"));

        // npm (일반 & Scoped)
        assertEquals("pkg:npm/react@18.2.0",
                CycloneDxSbomService.generatePurl("react", "18.2.0", "npm"));
        assertEquals("pkg:npm/%40angular/core@16.0.0",
                CycloneDxSbomService.generatePurl("@angular/core", "16.0.0", "npm"));

        // PyPI (Python)
        assertEquals("pkg:pypi/requests@2.31.0",
                CycloneDxSbomService.generatePurl("requests", "2.31.0", "PyPI(Python)"));

        // Cargo (Rust)
        assertEquals("pkg:cargo/serde@1.0.200",
                CycloneDxSbomService.generatePurl("serde", "1.0.200", "Cargo.lock"));

        // Go (Golang)
        assertEquals("pkg:golang/github.com/gin-gonic/gin@1.9.1",
                CycloneDxSbomService.generatePurl("github.com/gin-gonic/gin", "1.9.1", "go.sum"));

        // NuGet (C#)
        assertEquals("pkg:nuget/Newtonsoft.Json@13.0.3",
                CycloneDxSbomService.generatePurl("Newtonsoft.Json", "13.0.3", "NuGet"));

        // CocoaPods (iOS / Swift)
        assertEquals("pkg:cocoapods/AFNetworking@4.0.0",
                CycloneDxSbomService.generatePurl("AFNetworking", "4.0.0", "CocoaPods(iOS)"));

        // Pub (Dart / Flutter)
        assertEquals("pkg:pub/flutter_bloc@8.1.3",
                CycloneDxSbomService.generatePurl("flutter_bloc", "8.1.3", "Pub(Flutter/Dart)"));
    }

    @Test
    @DisplayName("OWASP CycloneDX v1.5 표준 규격에 부합하는 유효한 JSON BOM이 생성되어야 한다")
    void shouldBuildValidCycloneDx15Json() throws Exception {
        List<LLMAnalysisService.SbomPackageDetail> packages = List.of(
                new LLMAnalysisService.SbomPackageDetail("org.springframework.boot:spring-boot-starter-webmvc", "4.1.2", false, "Apache-2.0"),
                new LLMAnalysisService.SbomPackageDetail("org.apache.tomcat.embed:tomcat-embed-core", "11.0.27", true, "Apache-2.0")
        );

        List<LLMAnalysisService.VulnerabilityDetail> vulnerabilities = List.of(
                new LLMAnalysisService.VulnerabilityDetail("CVE-2026-43512", "org.apache.tomcat.embed:tomcat-embed-core",
                        "11.0.27", "11.0.28", "CRITICAL", "Tomcat Auth Bypass")
        );

        String json = service.buildCycloneDxJson(
                "pr-guard/sample-repo",
                12,
                "Java (Gradle) / Spring Boot 4.1.2",
                packages,
                vulnerabilities
        );

        assertNotNull(json);
        JsonNode root = objectMapper.readTree(json);

        // 1. 헤더 및 버전 규격 검증
        assertEquals("CycloneDX", root.path("bomFormat").asText());
        assertEquals("1.5", root.path("specVersion").asText());
        assertTrue(root.path("serialNumber").asText().startsWith("urn:uuid:"));
        assertEquals(1, root.path("version").asInt());

        // 2. 메타데이터 검증
        JsonNode metadata = root.path("metadata");
        assertNotNull(metadata.path("timestamp").asText());
        assertEquals("PR Guard", metadata.path("tools").get(0).path("vendor").asText());
        assertEquals("pr-guard/sample-repo", metadata.path("component").path("name").asText());
        assertEquals("PR #12", metadata.path("component").path("version").asText());
        assertEquals("Java (Gradle) / Spring Boot 4.1.2",
                metadata.path("component").path("properties").get(0).path("value").asText());

        // 3. 컴포넌트 목록 및 직접/간접 구분 검증
        JsonNode components = root.path("components");
        assertEquals(2, components.size());

        JsonNode comp1 = components.get(0);
        assertEquals("org.springframework.boot:spring-boot-starter-webmvc", comp1.path("name").asText());
        assertEquals("4.1.2", comp1.path("version").asText());
        assertEquals("required", comp1.path("scope").asText(), "직접 의존성은 required scope");
        assertEquals("direct", comp1.path("properties").get(0).path("value").asText());

        JsonNode comp2 = components.get(1);
        assertEquals("org.apache.tomcat.embed:tomcat-embed-core", comp2.path("name").asText());
        assertEquals("11.0.27", comp2.path("version").asText());
        assertEquals("optional", comp2.path("scope").asText(), "간접 전이 의존성은 optional scope");
        assertEquals("transitive", comp2.path("properties").get(0).path("value").asText());

        // 4. 의존성 트리 검증
        JsonNode dependencies = root.path("dependencies");
        assertTrue(dependencies.isArray());
        assertEquals("pr-guard/sample-repo", dependencies.get(0).path("ref").asText());
        assertEquals(1, dependencies.get(0).path("dependsOn").size());

        // 5. 취약점 (VEX) 연계 검증
        JsonNode vulns = root.path("vulnerabilities");
        assertEquals(1, vulns.size());
        assertEquals("CVE-2026-43512", vulns.get(0).path("id").asText());
        assertEquals("critical", vulns.get(0).path("ratings").get(0).path("severity").asText());
        assertEquals("pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@11.0.27",
                vulns.get(0).path("affects").get(0).path("ref").asText());

        // 6. 캐시 정상 보관 검증
        String cached = service.getSbom("pr-guard/sample-repo", 12);
        assertNotNull(cached);
        assertEquals(json, cached);
    }

    @Test
    @DisplayName("SHA-256 무결성 검증 해시가 정상 계산되어야 한다")
    void shouldComputeSha256Hash() {
        String testData = "CycloneDX-BOM-PR-Guard";
        String hash = CycloneDxSbomService.computeSha256(testData);

        assertNotNull(hash);
        assertEquals(64, hash.length(), "SHA-256 해시는 64자리 16진수여야 함");
    }

    @Test
    @DisplayName("저장소 내 설정 파일(properties, yaml, env)에서 실제 외부 SaaS 엔드포인트를 동적 감지해야 한다")
    void shouldDetectExternalServicesFromRepositoryFiles(@org.junit.jupiter.api.io.TempDir java.nio.file.Path tempDir) throws java.io.IOException {
        java.nio.file.Files.writeString(tempDir.resolve("application.properties"),
                "gemini.api.url=https://generativelanguage.googleapis.com/v1beta/models\ngithub.api.url=https://api.github.com\n");
        java.nio.file.Files.writeString(tempDir.resolve("application-payment.yml"),
                "toss:\n  payments:\n    url: https://api.tosspayments.com/v1/payments\n");

        List<CycloneDxSbomService.ExternalServiceDetail> services = service.detectExternalServices(tempDir);

        assertNotNull(services);
        assertEquals(3, services.size());
        assertTrue(services.stream().anyMatch(s -> s.name().contains("Gemini") && s.endpoint().contains("googleapis.com")));
        assertTrue(services.stream().anyMatch(s -> s.name().contains("GitHub") && s.endpoint().contains("github.com")));
        assertTrue(services.stream().anyMatch(s -> s.name().contains("Toss") && s.endpoint().contains("tosspayments.com")));
    }

    @Test
    @DisplayName("설정 파일에 명시되지 않은 서비스는 감지되지 않아야 하며, 소스코드 자체 리터럴로 인한 셀프 감지가 발생하지 않아야 한다")
    void shouldNotDetectUnconfiguredServices(@org.junit.jupiter.api.io.TempDir java.nio.file.Path tempDir) throws java.io.IOException {
        java.nio.file.Files.writeString(tempDir.resolve("application.properties"),
                "gemini.api.url=https://generativelanguage.googleapis.com/v1beta/models\ngithub.api.url=https://api.github.com\n");
        // 소스코드 파일 안에 온갖 문자열이 적혀 있어도 설정 파일이 아니므로 감지되지 않아야 함
        java.nio.file.Files.writeString(tempDir.resolve("MockService.java"),
                "String a = \"https://api.openai.com\";\nString b = \"https://api.stripe.com\";\n");

        List<CycloneDxSbomService.ExternalServiceDetail> services = service.detectExternalServices(tempDir);

        assertNotNull(services);
        assertEquals(2, services.size(), "오직 설정 파일(application.properties)에 기술된 Gemini와 GitHub만 감지되어야 함");
        assertFalse(services.stream().anyMatch(s -> s.name().contains("OpenAI")));
        assertFalse(services.stream().anyMatch(s -> s.name().contains("Stripe")));
    }

    @Test
    @DisplayName("PR Guard 프로젝트 자체를 스캔했을 때 application.properties에 설정된 Gemini와 GitHub API 2개만 감지되어야 한다")
    void shouldDetectOnlyConfiguredServicesOnPrGuardProject() {
        List<CycloneDxSbomService.ExternalServiceDetail> services = service.detectExternalServices(Path.of("."));
        assertNotNull(services);
        assertEquals(2, services.size(), "prguard 프로젝트는 오직 Gemini AI와 GitHub API 2개만 사용하므로 2개만 감지되어야 함 (10개 셀프 오탐 방지)");
        assertTrue(services.stream().anyMatch(s -> s.name().contains("Gemini")));
        assertTrue(services.stream().anyMatch(s -> s.name().contains("GitHub")));
        assertFalse(services.stream().anyMatch(s -> s.name().contains("Toss")));
        assertFalse(services.stream().anyMatch(s -> s.name().contains("Stripe")));
        assertFalse(services.stream().anyMatch(s -> s.name().contains("Kakao")));
        assertFalse(services.stream().anyMatch(s -> s.name().contains("OpenAI")));
        assertFalse(services.stream().anyMatch(s -> s.name().contains("Slack")));
    }

    @Test
    @DisplayName("CycloneDX 데이터를 기반으로 4대 카테고리(환경, 의존성, 외부 서비스, 무결성 링크) 마크다운 리포트가 정상 생성되어야 한다")
    void shouldRender4CategorySbomMarkdownReport() {
        List<LLMAnalysisService.SbomPackageDetail> packages = List.of(
                new LLMAnalysisService.SbomPackageDetail("react", "18.2.0", false, "MIT"),
                new LLMAnalysisService.SbomPackageDetail("loose-envify", "1.4.0", true, "Apache-2.0")
        );

        List<CycloneDxSbomService.ExternalServiceDetail> services = List.of(
                new CycloneDxSbomService.ExternalServiceDetail("Google Gemini AI", "Google Cloud",
                        "https://generativelanguage.googleapis.com", "AI 코드 분석 및 보안 진단")
        );

        String markdown = service.renderSbomMarkdownReport(
                "owner/my-web",
                42,
                "TypeScript (npm) / React",
                "FROM node:20-alpine\nWORKDIR /app\n",
                packages,
                services,
                "{\"bomFormat\":\"CycloneDX\"}"
        );

        assertNotNull(markdown);
        // 토글 헤더 검증
        assertTrue(markdown.contains("<details>"));
        assertTrue(markdown.contains("<summary><b>소프트웨어 자재 명세서 (SBOM) 구성 요소 보기 (총 3개)</b></summary>"));
        assertTrue(markdown.contains("OWASP CycloneDX v1.5 JSON"));

        // 카테고리 1: 런타임 및 빌드 환경 검증
        assertTrue(markdown.contains("### 1. 런타임 및 빌드 환경 (Environment)"));
        assertTrue(markdown.contains("`TypeScript`"));
        assertTrue(markdown.contains("`npm`"));
        assertTrue(markdown.contains("`React`"));
        assertTrue(markdown.contains("Docker (node:20-alpine)"));

        // 카테고리 2: 오픈소스 및 패키지 의존성 검증
        assertTrue(markdown.contains("### 2. 오픈소스 및 패키지 의존성 (Dependencies)"));
        assertTrue(markdown.contains("#### 직접 의존성 (Direct Dependencies - 1개)"));
        assertTrue(markdown.contains("| `react` | `18.2.0` | MIT | `pkg:npm/react@18.2.0` |"));
        assertTrue(markdown.contains("#### 간접 의존성 (Transitive Dependencies - 1개)"));
        assertTrue(markdown.contains("| `loose-envify` | `1.4.0` | Apache-2.0 | `pkg:npm/loose-envify@1.4.0` |"));

        // 카테고리 3: 외부 연동 서비스 및 SaaS 자산 검증
        assertTrue(markdown.contains("### 3. 외부 연동 서비스 및 SaaS 자산 (External Services)"));
        assertTrue(markdown.contains("| `Google Gemini AI` | Google Cloud | `https://generativelanguage.googleapis.com` | AI 코드 분석 및 보안 진단 |"));

        // 카테고리 4: 무결성 검증 및 다운로드 링크 검증
        assertTrue(markdown.contains("### 4. 무결성 원본 데이터 및 기계 판독 다운로드"));
        assertTrue(markdown.contains("https://prguard.onrender.com/api/sbom/owner/my-web/42"));
        assertTrue(markdown.contains("SHA-256 무결성 해시:"));
        assertTrue(markdown.contains("</details>"));
    }
}

