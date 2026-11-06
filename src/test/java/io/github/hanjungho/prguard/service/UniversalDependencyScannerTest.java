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
                    id 'org.springframework.boot' version '3.4.1'
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
        assertTrue(packages.size() >= 3, "선언된 패키지가 검출되어야 함");
        assertTrue(packages.stream().anyMatch(p -> p.name().contains("spring-boot-starter-web") && "3.4.1".equals(p.version())));
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
    @DisplayName("실제 Gradle Wrapper 실행 결과 트리를 통해 직접 및 전이 의존성을 파싱할 수 있어야 한다")
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

        LLMAnalysisService.SbomPackageDetail webmvc = map.get("org.springframework.boot:spring-boot-starter-webmvc");
        assertNotNull(webmvc);
        assertFalse(webmvc.indirect(), "webmvc는 직접 의존성이어야 함");
        assertEquals("4.1.2", webmvc.version());

        LLMAnalysisService.SbomPackageDetail jjwt = map.get("io.jsonwebtoken:jjwt-api");
        assertNotNull(jjwt);
        assertFalse(jjwt.indirect(), "jjwt-api는 직접 의존성이어야 함");
        assertEquals("0.12.6", jjwt.version());

        LLMAnalysisService.SbomPackageDetail tomcat = map.get("org.apache.tomcat.embed:tomcat-embed-core");
        assertNotNull(tomcat);
        assertTrue(tomcat.indirect(), "tomcat-embed-core는 간접 의존성이어야 함");
        assertEquals("11.0.27", tomcat.version());
    }

    @Test
    @DisplayName("스캐너는 절대로 디스크에 임의의 가짜 파일(gradle.lockfile, requirements.txt 등)을 생성해서는 안 된다")
    void shouldNeverCreateSyntheticFilesOnDisk(@TempDir Path tempDir) throws IOException {
        String gradleContent = """
                plugins {
                    id 'org.springframework.boot' version '3.4.1'
                }
                dependencies {
                    implementation 'org.springframework.boot:spring-boot-starter-web'
                }
                """;
        Files.writeString(tempDir.resolve("build.gradle"), gradleContent);

        String pyCode = "import requests\nimport json\n";
        Files.writeString(tempDir.resolve("script.py"), pyCode);

        // 스캔 실행
        List<LLMAnalysisService.SbomPackageDetail> packages = scanner.scan(tempDir);

        assertNotNull(packages);
        // 디스크에 가짜 파일이 전혀 생성되지 않았는지 철저히 검증
        assertFalse(Files.exists(tempDir.resolve("gradle.lockfile")), "가짜 gradle.lockfile이 생성되어서는 안 됨");
        assertFalse(Files.exists(tempDir.resolve("requirements.txt")), "가짜 requirements.txt가 생성되어서는 안 됨");
        assertFalse(Files.exists(tempDir.resolve("package.json")), "가짜 package.json이 생성되어서는 안 됨");
        assertFalse(Files.exists(tempDir.resolve("Cargo.toml")), "가짜 Cargo.toml이 생성되어서는 안 됨");

        // 가짜 하위 의존성(2000년대 Tomcat 등)이 임의 주입되지 않았는지 검증
        assertFalse(packages.stream().anyMatch(p -> p.name().contains("tomcat-embed-core")), "선언되지 않은 가짜 Tomcat이 포함되어서는 안 됨");
    }

    @Test
    @DisplayName("저장소에 실제 커밋된 gradle.lockfile이 존재할 경우 정확하게 패키지와 버전을 읽어와야 한다")
    void shouldParseRealGradleLockfileIfCommitted(@TempDir Path tempDir) throws IOException {
        String lockContent = """
                # Real committed lockfile
                org.springframework.boot:spring-boot-starter-web:3.4.1=runtimeClasspath
                com.fasterxml.jackson.core:jackson-databind:2.17.2=runtimeClasspath
                empty=annotationProcessor
                """;
        Files.writeString(tempDir.resolve("gradle.lockfile"), lockContent);

        List<LLMAnalysisService.SbomPackageDetail> packages = scanner.scan(tempDir);

        assertNotNull(packages);
        assertEquals(2, packages.size());
        assertTrue(packages.stream().anyMatch(p ->
                p.name().equals("org.springframework.boot:spring-boot-starter-web") && "3.4.1".equals(p.version())));
        assertTrue(packages.stream().anyMatch(p ->
                p.name().equals("com.fasterxml.jackson.core:jackson-databind") && "2.17.2".equals(p.version())));
    }

    @Test
    @DisplayName("저장소에 실제 커밋된 package-lock.json이 존재할 경우 정확하게 패키지를 읽어와야 한다")
    void shouldParseRealPackageLockJsonIfCommitted(@TempDir Path tempDir) throws IOException {
        String lockContent = """
                {
                  "name": "my-node-app",
                  "version": "1.0.0",
                  "lockfileVersion": 3,
                  "packages": {
                    "": {
                      "name": "my-node-app",
                      "version": "1.0.0"
                    },
                    "node_modules/express": {
                      "version": "4.19.2"
                    },
                    "node_modules/cors": {
                      "version": "2.8.5"
                    }
                  }
                }
                """;
        Files.writeString(tempDir.resolve("package-lock.json"), lockContent);

        List<LLMAnalysisService.SbomPackageDetail> packages = scanner.scan(tempDir);

        assertNotNull(packages);
        assertEquals(2, packages.size());
        assertTrue(packages.stream().anyMatch(p -> p.name().equals("express") && "4.19.2".equals(p.version())));
        assertTrue(packages.stream().anyMatch(p -> p.name().equals("cors") && "2.8.5".equals(p.version())));
    }

    @Test
    @DisplayName("저장소에 실제 커밋된 Cargo.lock이 존재할 경우 정확하게 패키지를 읽어와야 한다")
    void shouldParseRealCargoLockIfCommitted(@TempDir Path tempDir) throws IOException {
        String lockContent = """
                # This file is automatically @generated by Cargo.
                version = 3

                [[package]]
                name = "serde"
                version = "1.0.200"

                [[package]]
                name = "tokio"
                version = "1.38.0"
                """;
        Files.writeString(tempDir.resolve("Cargo.lock"), lockContent);

        List<LLMAnalysisService.SbomPackageDetail> packages = scanner.scan(tempDir);

        assertNotNull(packages);
        assertEquals(2, packages.size());
        assertTrue(packages.stream().anyMatch(p -> p.name().equals("serde") && "1.0.200".equals(p.version())));
        assertTrue(packages.stream().anyMatch(p -> p.name().equals("tokio") && "1.38.0".equals(p.version())));
    }

    @Test
    @DisplayName("Java Gradle Spring Boot 환경이 정확하게 감지되어야 한다")
    void shouldDetectProjectEnvironmentForJavaGradleSpringBoot(@TempDir Path tempDir) throws IOException {
        Files.writeString(tempDir.resolve("build.gradle"), "plugins { id 'org.springframework.boot' version '3.2.0' }");
        List<LLMAnalysisService.SbomPackageDetail> pkgs = List.of(
                new LLMAnalysisService.SbomPackageDetail("org.springframework.boot:spring-boot", "3.2.0", false)
        );

        UniversalDependencyScanner.ProjectEnvironment env = scanner.detectProjectEnvironment(tempDir, pkgs);

        assertEquals("Java", env.language());
        assertEquals("Gradle", env.buildTool());
        assertTrue(env.framework().contains("Spring Boot"));
        assertEquals("Java (Gradle) / Spring Boot 3.2.0", env.toSummaryString());
    }

    @Test
    @DisplayName("build.gradle 또는 pom.xml에 Java 버전(17, 21 등)이 명시된 경우 언어 항목에 버전이 함께 감지되어야 한다")
    void shouldDetectJavaVersionWhenSpecifiedInManifest(@TempDir Path tempDir) throws IOException {
        String gradleWithToolchain = """
                plugins {
                    id 'java'
                    id 'org.springframework.boot' version '4.1.2'
                }
                java {
                    toolchain {
                        languageVersion = JavaLanguageVersion.of(17)
                    }
                }
                """;
        Files.writeString(tempDir.resolve("build.gradle"), gradleWithToolchain);
        List<LLMAnalysisService.SbomPackageDetail> pkgs = List.of(
                new LLMAnalysisService.SbomPackageDetail("org.springframework.boot:spring-boot", "4.1.2", false)
        );

        UniversalDependencyScanner.ProjectEnvironment env = scanner.detectProjectEnvironment(tempDir, pkgs);

        assertEquals("Java 17", env.language(), "toolchain languageVersion 17을 감지하여 Java 17로 표현되어야 함");
        assertEquals("Gradle", env.buildTool());
        assertEquals("Java 17 (Gradle) / Spring Boot 4.1.2", env.toSummaryString());
    }

    @Test
    @DisplayName("TypeScript Node.js React 환경이 정확하게 감지되어야 한다")
    void shouldDetectProjectEnvironmentForNodeTypeScriptReact(@TempDir Path tempDir) throws IOException {
        Files.writeString(tempDir.resolve("package.json"), "{\"name\": \"my-app\"}");
        Files.writeString(tempDir.resolve("tsconfig.json"), "{}");
        Files.writeString(tempDir.resolve("package-lock.json"), "{}");
        List<LLMAnalysisService.SbomPackageDetail> pkgs = List.of(
                new LLMAnalysisService.SbomPackageDetail("react", "18.2.0", false)
        );

        UniversalDependencyScanner.ProjectEnvironment env = scanner.detectProjectEnvironment(tempDir, pkgs);

        assertEquals("TypeScript", env.language());
        assertEquals("npm", env.buildTool());
        assertEquals("React", env.framework());
        assertEquals("TypeScript (npm) / React", env.toSummaryString());
    }

    @Test
    @DisplayName("npm package-lock.json v3에서 root packages['']의 직접 의존성과 하위 간접 의존성을 정확히 구분해야 한다")
    void shouldClassifyDirectAndIndirectInPackageLockJsonV3(@TempDir Path tempDir) throws IOException {
        String lockContent = """
                {
                  "name": "unt-work-hub",
                  "version": "1.0.0",
                  "lockfileVersion": 3,
                  "packages": {
                    "": {
                      "name": "unt-work-hub",
                      "dependencies": {
                        "react": "^18.2.0"
                      }
                    },
                    "node_modules/react": {
                      "version": "18.2.0"
                    },
                    "node_modules/loose-envify": {
                      "version": "1.4.0"
                    }
                  }
                }
                """;
        Files.writeString(tempDir.resolve("package-lock.json"), lockContent);

        List<LLMAnalysisService.SbomPackageDetail> packages = scanner.scan(tempDir);

        assertNotNull(packages);
        assertEquals(2, packages.size());

        LLMAnalysisService.SbomPackageDetail react = packages.stream().filter(p -> p.name().equals("react")).findFirst().orElseThrow();
        assertFalse(react.indirect(), "packages['']에 선언된 react는 직접 의존성(indirect=false)");

        LLMAnalysisService.SbomPackageDetail looseEnvify = packages.stream().filter(p -> p.name().equals("loose-envify")).findFirst().orElseThrow();
        assertTrue(looseEnvify.indirect(), "전이 의존성 loose-envify는 간접 의존성(indirect=true)");
    }

    @Test
    @DisplayName("루트에 package.json이 없더라도 하위 패키지 목록(safePackages)을 역추론하여 언어와 프레임워크를 식별해야 한다")
    void shouldDetectEnvironmentFromPackagesWhenRootManifestInSubdir(@TempDir Path tempDir) throws IOException {
        Files.writeString(tempDir.resolve("App.tsx"), "export const App = () => <div>Hello</div>;");
        List<LLMAnalysisService.SbomPackageDetail> pkgs = List.of(
                new LLMAnalysisService.SbomPackageDetail("react", "18.2.0", false, "npm-lockfile"),
                new LLMAnalysisService.SbomPackageDetail("loose-envify", "1.4.0", true, "npm-lockfile")
        );

        UniversalDependencyScanner.ProjectEnvironment env = scanner.detectProjectEnvironment(tempDir, pkgs);

        assertEquals("TypeScript", env.language());
        assertEquals("npm", env.buildTool());
        assertEquals("React", env.framework());
        assertEquals("TypeScript (npm) / React", env.toSummaryString());
    }

    @Test
    @DisplayName("yarn.lock 파일에서 패키지명과 실제 버전을 간접 의존성으로 정확히 추출해야 한다")
    void shouldExtractYarnLockDependencies(@TempDir Path tempDir) throws IOException {
        String yarnContent = """
                # yarn lockfile v1
                "@babel/core@^7.0.0", "@babel/core@^7.1.0":
                  version "7.22.5"
                  resolved "https://registry.yarnpkg.com/@babel/core/-/core-7.22.5.tgz"
                
                "lodash@^4.17.21":
                  version "4.17.21"
                  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz"
                """;
        Files.writeString(tempDir.resolve("yarn.lock"), yarnContent);

        List<LLMAnalysisService.SbomPackageDetail> packages = scanner.scan(tempDir);

        assertNotNull(packages);
        assertEquals(2, packages.size());
        assertTrue(packages.stream().anyMatch(p -> p.name().equals("@babel/core") && p.version().equals("7.22.5") && p.indirect()));
        assertTrue(packages.stream().anyMatch(p -> p.name().equals("lodash") && p.version().equals("4.17.21") && p.indirect()));
    }

    @Test
    @DisplayName("Python poetry.lock 파일에서 패키지명과 버전을 추출해야 한다")
    void shouldExtractPoetryLockDependencies(@TempDir Path tempDir) throws IOException {
        String poetryContent = """
                [[package]]
                name = "requests"
                version = "2.31.0"
                description = "Python HTTP for Humans."
                
                [[package]]
                name = "urllib3"
                version = "2.0.7"
                description = "HTTP library with thread-safe connection pooling."
                """;
        Files.writeString(tempDir.resolve("poetry.lock"), poetryContent);

        List<LLMAnalysisService.SbomPackageDetail> packages = scanner.scan(tempDir);

        assertNotNull(packages);
        assertEquals(2, packages.size());
        assertTrue(packages.stream().anyMatch(p -> p.name().equals("requests") && p.version().equals("2.31.0")));
        assertTrue(packages.stream().anyMatch(p -> p.name().equals("urllib3") && p.version().equals("2.0.7")));
    }

    @Test
    @DisplayName("PHP composer.lock 파일에서 패키지 목록을 추출해야 한다")
    void shouldExtractComposerLockDependencies(@TempDir Path tempDir) throws IOException {
        String composerContent = """
                {
                    "packages": [
                        {
                            "name": "guzzlehttp/guzzle",
                            "version": "7.8.1"
                        },
                        {
                            "name": "monolog/monolog",
                            "version": "v3.5.0"
                        }
                    ]
                }
                """;
        Files.writeString(tempDir.resolve("composer.lock"), composerContent);

        List<LLMAnalysisService.SbomPackageDetail> packages = scanner.scan(tempDir);

        assertNotNull(packages);
        assertEquals(2, packages.size());
        assertTrue(packages.stream().anyMatch(p -> p.name().equals("guzzlehttp/guzzle") && p.version().equals("7.8.1")));
        assertTrue(packages.stream().anyMatch(p -> p.name().equals("monolog/monolog") && p.version().equals("3.5.0")));
    }
}
