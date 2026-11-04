package io.github.hanjungho.prguard.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

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
}

