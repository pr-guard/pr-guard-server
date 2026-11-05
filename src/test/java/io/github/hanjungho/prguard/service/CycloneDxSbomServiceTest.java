package io.github.hanjungho.prguard.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

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
}
