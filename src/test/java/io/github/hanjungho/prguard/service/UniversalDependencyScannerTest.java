package io.github.hanjungho.prguard.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class UniversalDependencyScannerTest {

    private UniversalDependencyScanner scanner;

    @BeforeEach
    void setUp() {
        scanner = new UniversalDependencyScanner(new ObjectMapper());
    }

    @Test
    @DisplayName("Java/Kotlin Gradle 프로젝트의 build.gradle 매니페스트에서 직접 의존성을 추출할 수 있어야 한다")
    void shouldExtractGradleDependencies(@TempDir Path tempDir) throws IOException {
        String gradleContent = """
                plugins {
                    id 'org.springframework.boot' version '3.2.0'
                }
                dependencies {
                    implementation 'org.springframework.boot:spring-boot-starter-web'
                    implementation 'io.jsonwebtoken:jjwt-api:0.12.3'
                    compileOnly 'org.projectlombok:lombok'
                }
                """;
        Files.writeString(tempDir.resolve("build.gradle"), gradleContent);

        List<LLMAnalysisService.SbomPackageDetail> packages = scanner.scan(tempDir);

        assertNotNull(packages);
        assertTrue(packages.size() >= 3, "최소 3개 이상의 패키지가 검출되어야 함");
        assertTrue(packages.stream().anyMatch(p -> p.name().contains("spring-boot-starter-web")));
        assertTrue(packages.stream().anyMatch(p -> p.name().contains("jjwt-api") && p.version().equals("0.12.3")));
    }

    @Test
    @DisplayName("C# / .NET 프로젝트의 *.csproj 매니페스트에서 패키지를 추출할 수 있어야 한다")
    void shouldExtractCsprojDependencies(@TempDir Path tempDir) throws IOException {
        String csprojContent = """
                <Project Sdk="Microsoft.NET.Sdk">
                  <ItemGroup>
                    <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
                    <PackageReference Include="Microsoft.EntityFrameworkCore" Version="7.0.5" />
                  </ItemGroup>
                </Project>
                """;
        Files.writeString(tempDir.resolve("MyService.csproj"), csprojContent);

        List<LLMAnalysisService.SbomPackageDetail> packages = scanner.scan(tempDir);

        assertNotNull(packages);
        assertEquals(2, packages.size());
        assertTrue(packages.stream().anyMatch(p -> p.name().equals("Newtonsoft.Json") && p.version().equals("13.0.3")));
        assertTrue(packages.stream().anyMatch(p -> p.name().equals("Microsoft.EntityFrameworkCore") && p.version().equals("7.0.5")));
    }

    @Test
    @DisplayName("C / C++ 프로젝트의 conanfile.txt 및 CMakeLists.txt에서 라이브러리를 추출할 수 있어야 한다")
    void shouldExtractCppDependencies(@TempDir Path tempDir) throws IOException {
        String conanContent = """
                [requires]
                boost/1.81.0
                fmt/9.1.0
                """;
        Files.writeString(tempDir.resolve("conanfile.txt"), conanContent);

        String cmakeContent = """
                cmake_minimum_required(VERSION 3.20)
                find_package(OpenCV REQUIRED)
                """;
        Files.writeString(tempDir.resolve("CMakeLists.txt"), cmakeContent);

        List<LLMAnalysisService.SbomPackageDetail> packages = scanner.scan(tempDir);

        assertNotNull(packages);
        assertEquals(3, packages.size());
        assertTrue(packages.stream().anyMatch(p -> p.name().equals("boost") && p.version().equals("1.81.0")));
        assertTrue(packages.stream().anyMatch(p -> p.name().equals("fmt") && p.version().equals("9.1.0")));
        assertTrue(packages.stream().anyMatch(p -> p.name().equals("OpenCV")));
    }

    @Test
    @DisplayName("모바일(iOS Podfile / Flutter pubspec.yaml) 매니페스트에서 패키지를 추출할 수 있어야 한다")
    void shouldExtractMobileDependencies(@TempDir Path tempDir) throws IOException {
        String podfileContent = """
                target 'App' do
                  pod 'Alamofire', '~> 5.4'
                  pod 'SnapKit'
                end
                """;
        Files.writeString(tempDir.resolve("Podfile"), podfileContent);

        String pubspecContent = """
                name: my_flutter_app
                dependencies:
                  flutter_bloc: ^8.0.0
                  http: '0.13.4'
                """;
        Files.writeString(tempDir.resolve("pubspec.yaml"), pubspecContent);

        List<LLMAnalysisService.SbomPackageDetail> packages = scanner.scan(tempDir);

        assertNotNull(packages);
        assertEquals(4, packages.size());
        assertTrue(packages.stream().anyMatch(p -> p.name().equals("Alamofire")));
        assertTrue(packages.stream().anyMatch(p -> p.name().equals("flutter_bloc") && p.version().equals("^8.0.0")));
    }

    @Test
    @DisplayName("게임 Unity 프로젝트의 Packages/manifest.json에서 패키지를 추출할 수 있어야 한다")
    void shouldExtractUnityDependencies(@TempDir Path tempDir) throws IOException {
        Path packagesDir = tempDir.resolve("Packages");
        Files.createDirectories(packagesDir);

        String manifestJson = """
                {
                  "dependencies": {
                    "com.unity.ugui": "1.0.0",
                    "com.unity.render-pipelines.universal": "14.0.8"
                  }
                }
                """;
        Files.writeString(packagesDir.resolve("manifest.json"), manifestJson);

        List<LLMAnalysisService.SbomPackageDetail> packages = scanner.scan(tempDir);

        assertNotNull(packages);
        assertEquals(2, packages.size());
        assertTrue(packages.stream().anyMatch(p -> p.name().equals("com.unity.ugui") && p.version().equals("1.0.0")));
    }

    @Test
    @DisplayName("Gradle 의존성 트리 출력에서 직접 의존성과 전이(간접) 의존성을 정확히 구분하여 파싱해야 한다")
    void shouldParseGradleDependencyTreeOutputWithDirectAndIndirectDependencies() {
        String treeOutput = """
                ------------------------------------------------------------
                Root project 'my-app'
                ------------------------------------------------------------

                runtimeClasspath - Runtime classpath of source set 'main'.
                +--- org.springframework.boot:spring-boot-starter-webmvc -> 4.1.2
                |    +--- org.springframework.boot:spring-boot-starter:4.1.2
                |    |    +--- ch.qos.logback:logback-classic:1.5.38
                |    |    |    \\--- org.slf4j:slf4j-api:2.0.17 -> 2.0.20
                |    |    \\--- org.yaml:snakeyaml:2.6
                |    +--- org.apache.tomcat.embed:tomcat-embed-core:11.0.27
                |    \\--- org.springframework:spring-webmvc:7.0.10 (*)
                +--- com.fasterxml.jackson.core:jackson-databind -> 2.21.7
                |    +--- com.fasterxml.jackson.core:jackson-annotations:2.21 (c)
                |    \\--- com.fasterxml.jackson.core:jackson-core:2.21.7
                \\--- io.jsonwebtoken:jjwt-api:0.12.6
                """;

        Map<String, LLMAnalysisService.SbomPackageDetail> map = new LinkedHashMap<>();
        scanner.parseGradleDependencyTreeOutput(treeOutput, map);

        assertFalse(map.isEmpty());

        // 직접 의존성 검증 (indent 없음)
        LLMAnalysisService.SbomPackageDetail webmvc = map.get("org.springframework.boot:spring-boot-starter-webmvc");
        assertNotNull(webmvc);
        assertFalse(webmvc.indirect(), "webmvc는 직접 의존성이어야 함");
        assertEquals("4.1.2", webmvc.version());

        LLMAnalysisService.SbomPackageDetail jjwt = map.get("io.jsonwebtoken:jjwt-api");
        assertNotNull(jjwt);
        assertFalse(jjwt.indirect(), "jjwt-api는 직접 의존성이어야 함");
        assertEquals("0.12.6", jjwt.version());

        // 간접(전이) 의존성 검증 (indent 있음)
        LLMAnalysisService.SbomPackageDetail tomcat = map.get("org.apache.tomcat.embed:tomcat-embed-core");
        assertNotNull(tomcat);
        assertTrue(tomcat.indirect(), "tomcat-embed-core는 간접 의존성이어야 함");
        assertEquals("11.0.27", tomcat.version());

        LLMAnalysisService.SbomPackageDetail logback = map.get("ch.qos.logback:logback-classic");
        assertNotNull(logback);
        assertTrue(logback.indirect(), "logback-classic은 간접 의존성이어야 함");

        LLMAnalysisService.SbomPackageDetail slf4j = map.get("org.slf4j:slf4j-api");
        assertNotNull(slf4j);
        assertTrue(slf4j.indirect());
        assertEquals("2.0.20", slf4j.version(), "버전 업그레이드(->)가 적용되어 2.0.20이어야 함");

        // (c) 제약조건(BOM)은 제외되어야 함
        assertNull(map.get("com.fasterxml.jackson.core:jackson-annotations"), "(c) 제약조건은 제외되어야 함");

        // (*) 중복 하위 트리 표시는 정상 제거되고 패키지가 포함되어야 함
        LLMAnalysisService.SbomPackageDetail webmvcSpring = map.get("org.springframework:spring-webmvc");
        assertNotNull(webmvcSpring);
        assertTrue(webmvcSpring.indirect());
        assertEquals("7.0.10", webmvcSpring.version());
    }

    @Test
    @DisplayName("Lock 파일이 없는 Gradle 프로젝트 스캔 시 Trivy가 감지할 수 있도록 gradle.lockfile을 자동 합성 생성해야 한다")
    void shouldSynthesizeGradleLockfileWhenAbsent(@TempDir Path tempDir) throws IOException {
        String gradleContent = """
                plugins {
                    id 'org.springframework.boot' version '3.2.0'
                }
                dependencies {
                    implementation 'org.springframework.boot:spring-boot-starter-web'
                    implementation 'io.jsonwebtoken:jjwt-api:0.12.3'
                }
                """;
        Files.writeString(tempDir.resolve("build.gradle"), gradleContent);

        List<LLMAnalysisService.SbomPackageDetail> packages = scanner.scan(tempDir);

        assertNotNull(packages);
        assertTrue(packages.size() > 2, "Fallback을 통해 간접 의존성까지 확장 수집되어야 함");
        assertTrue(packages.stream().anyMatch(LLMAnalysisService.SbomPackageDetail::indirect), "최소 1개 이상의 간접 의존성이 존재해야 함");

        // gradle.lockfile 생성 확인
        Path lockfile = tempDir.resolve("gradle.lockfile");
        assertTrue(Files.exists(lockfile), "Trivy 연동을 위한 gradle.lockfile이 자동 생성되어야 함");

        String lockfileContent = Files.readString(lockfile);
        assertTrue(lockfileContent.contains("=runtimeClasspath"), "Gradle lockfile 표준 형식을 따라야 함");
        assertTrue(lockfileContent.contains("io.jsonwebtoken:jjwt-api:0.12.3=runtimeClasspath"));
    }
}

