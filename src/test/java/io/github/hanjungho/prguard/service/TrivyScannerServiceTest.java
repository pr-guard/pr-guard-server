package io.github.hanjungho.prguard.service;

import io.github.hanjungho.prguard.dto.PrguardConfig;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class TrivyScannerServiceTest {

    private final TrivyScannerService service = new TrivyScannerService();

    @Test
    @DisplayName("런타임 설정 파일(Dockerfile, .nvmrc, package.json)이 정상적으로 추출되어야 한다")
    void shouldExtractRuntimeContextSuccessfully(@TempDir Path tempDir) throws IOException {
        Files.writeString(tempDir.resolve("Dockerfile"), "FROM node:18-alpine\nWORKDIR /app");
        Files.writeString(tempDir.resolve(".nvmrc"), "v20.10.0");
        Files.writeString(tempDir.resolve("package.json"), "{\"engines\": {\"node\": \">=18.0.0\"}}");

        String context = service.extractRuntimeContext(tempDir);

        assertNotNull(context);
        assertTrue(context.contains("--- [Dockerfile] ---"));
        assertTrue(context.contains("FROM node:18-alpine"));
        assertTrue(context.contains("--- [.nvmrc] ---"));
        assertTrue(context.contains("v20.10.0"));
        assertTrue(context.contains("--- [package.json (런타임 및 프레임워크 버전)] ---"));
        assertTrue(context.contains("\">=18.0.0\""));
    }

    @Test
    @DisplayName("설정 파일이 전혀 없을 경우 기본 안내 문구가 반환되어야 한다")
    void shouldReturnDefaultMessageWhenNoConfigFiles(@TempDir Path tempDir) {
        String context = service.extractRuntimeContext(tempDir);

        assertNotNull(context);
        assertEquals("(탐지된 런타임/빌드 환경 설정 파일 없음)", context);
    }

    @Test
    @DisplayName(".prguard.yml 파일이 존재할 때 커스텀 보안 정책이 정상 파싱되어야 한다")
    void shouldExtractPrguardConfigWhenYamlExists(@TempDir Path tempDir) throws IOException {
        String yamlContent = """
                ignore_severities:
                  - LOW
                  - MEDIUM
                ignore_packages:
                  - lodash
                  - internal-core
                ignore_cves:
                  - CVE-2023-9999
                block_severities:
                  - CRITICAL
                """;
        Files.writeString(tempDir.resolve(".prguard.yml"), yamlContent);

        PrguardConfig config = service.extractPrguardConfig(tempDir);

        assertNotNull(config);
        assertTrue(config.getIgnoreSeverities().contains("LOW"));
        assertTrue(config.getIgnoreSeverities().contains("MEDIUM"));
        assertTrue(config.getIgnorePackages().contains("lodash"));
        assertTrue(config.getIgnoreCves().contains("CVE-2023-9999"));
        assertEquals(1, config.getBlockSeverities().size());
        assertTrue(config.getBlockSeverities().contains("CRITICAL"));

        // 예외 규칙 동작 검증
        assertTrue(config.isVulnerabilityIgnored("CVE-1", "lodash", "HIGH"));
        assertTrue(config.isVulnerabilityIgnored("CVE-2023-9999", "other-pkg", "HIGH"));
        assertTrue(config.isVulnerabilityIgnored("CVE-3", "other-pkg", "LOW"));
        assertFalse(config.isVulnerabilityIgnored("CVE-4", "react", "HIGH"));

        // 차단 기준 동작 검증
        assertTrue(config.shouldBlock("CRITICAL"));
        assertFalse(config.shouldBlock("HIGH"));
    }

    @Test
    @DisplayName(".prguard.yml 파일이 없을 때 기본 정책이 반환되어야 한다")
    void shouldReturnDefaultConfigWhenNoYamlFile(@TempDir Path tempDir) {
        PrguardConfig config = service.extractPrguardConfig(tempDir);

        assertNotNull(config);
        assertTrue(config.getIgnoreSeverities().isEmpty());
        assertTrue(config.getIgnorePackages().isEmpty());
        assertTrue(config.getBlockSeverities().contains("CRITICAL"));
        assertTrue(config.getBlockSeverities().contains("HIGH"));
    }
}
