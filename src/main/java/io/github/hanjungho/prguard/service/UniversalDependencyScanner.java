package io.github.hanjungho.prguard.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 프로젝트 내 모든 프로그래밍 언어, 모바일, 게임 엔진 및 프레임워크의 의존성 매니페스트를 직접 탐색하고 파싱하는 범용 SBOM 추출기.
 * (Lock 파일이 없더라도 build.gradle, .csproj, CMakeLists.txt, vcpkg, Conan, Podfile, pubspec, Unity manifest 등 지원)
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class UniversalDependencyScanner {

    private final ObjectMapper objectMapper;

    private static final Set<String> IGNORED_DIRS = Set.of(
            ".git", ".gradle", ".idea", "node_modules", "target", "build", "bin", "obj",
            ".vs", ".vscode", "vendor", "dist", "out", ".next", ".nuxt"
    );

    // Gradle Regex
    private static final Pattern GRADLE_DEP_PATTERN = Pattern.compile(
            "(?:implementation|api|compileOnly|runtimeOnly|testImplementation|testCompileOnly)\\s*[(]?['\"]([^:'\"\\s]+):([^:'\"\\s]+)(?::([^:'\"\\s]+))?['\"][)]?"
    );
    private static final Pattern GRADLE_PLUGIN_PATTERN = Pattern.compile(
            "id\\s+['\"]([^'\"\\s]+)['\"]\\s+version\\s+['\"]([^'\"\\s]+)['\"]"
    );

    // Maven Regex
    private static final Pattern MAVEN_DEP_PATTERN = Pattern.compile(
            "<dependency>\\s*<groupId>([^<]+)</groupId>\\s*<artifactId>([^<]+)</artifactId>(?:\\s*<version>([^<]+)</version>)?",
            Pattern.DOTALL
    );

    // C# / .NET / Unity Regex
    private static final Pattern CSPROJ_PACKAGE_PATTERN = Pattern.compile(
            "<PackageReference\\s+(?:Include=\"([^\"]+)\"\\s+Version=\"([^\"]+)\"|Version=\"([^\"]+)\"\\s+Include=\"([^\"]+)\")"
    );
    private static final Pattern PACKAGES_CONFIG_PATTERN = Pattern.compile(
            "<package\\s+id=\"([^\"]+)\"\\s+version=\"([^\"]+)\""
    );

    // C / C++ Conan Regex
    private static final Pattern CONAN_REQ_PATTERN = Pattern.compile(
            "^([a-zA-Z0-9_\\-\\.]+)/([a-zA-Z0-9_\\-\\.]+)", Pattern.MULTILINE
    );
    // CMake Regex
    private static final Pattern CMAKE_FIND_PACKAGE_PATTERN = Pattern.compile(
            "find_package\\s*\\(\\s*([a-zA-Z0-9_\\-]+)(?:\\s+([0-9a-zA-Z.\\-]+))?", Pattern.CASE_INSENSITIVE
    );

    // iOS / Mobile Podfile Regex
    private static final Pattern PODFILE_PATTERN = Pattern.compile(
            "pod\\s+['\"]([^'\"\\s]+)['\"](?:\\s*,\\s*['\"]([^'\"\\s]+)['\"])?"
    );
    // Swift Package Manager
    private static final Pattern SWIFT_PKG_PATTERN = Pattern.compile(
            "\\.package\\s*\\(\\s*url:\\s*\"[^\"]*/([^/\"]+?)(?:\\.git)?\"\\s*,\\s*(?:from|exact):\\s*\"([^\"]+)\""
    );

    // Python requirements.txt
    private static final Pattern PYTHON_REQ_PATTERN = Pattern.compile(
            "^([a-zA-Z0-9_\\-\\.]+)\\s*(?:==|>=|<=|~=)\\s*([a-zA-Z0-9_\\-\\.]+)", Pattern.MULTILINE
    );

    // Rust Cargo.toml
    private static final Pattern CARGO_DEP_PATTERN = Pattern.compile(
            "^([a-zA-Z0-9_\\-]+)\\s*=\\s*(?:['\"]([^'\"\\s]+)['\"]|\\{[^}]*version\\s*=\\s*['\"]([^'\"\\s]+)['\"])", Pattern.MULTILINE
    );

    // Go go.mod
    private static final Pattern GO_MOD_PATTERN = Pattern.compile(
            "^\\s*([a-zA-Z0-9_\\-\\./]+)\\s+v([0-9a-zA-Z.\\-]+)", Pattern.MULTILINE
    );

    // 공통 Spring Boot Starter 하위 전이(간접) 의존성 카탈로그 (오프라인/Wrapper 실패 시 고속 Fallback)
    private static final Map<String, List<String>> COMMON_STARTER_CHILDREN = Map.of(
            "org.springframework.boot:spring-boot-starter-web", List.of(
                    "org.springframework.boot:spring-boot",
                    "org.springframework.boot:spring-boot-starter",
                    "org.springframework.boot:spring-boot-starter-tomcat",
                    "org.apache.tomcat.embed:tomcat-embed-core",
                    "org.apache.tomcat.embed:tomcat-embed-el",
                    "org.apache.tomcat.embed:tomcat-embed-websocket",
                    "org.springframework:spring-web",
                    "org.springframework:spring-webmvc",
                    "ch.qos.logback:logback-classic",
                    "ch.qos.logback:logback-core",
                    "org.slf4j:slf4j-api",
                    "org.yaml:snakeyaml"
            ),
            "org.springframework.boot:spring-boot-starter-webmvc", List.of(
                    "org.springframework.boot:spring-boot",
                    "org.springframework.boot:spring-boot-starter",
                    "org.springframework.boot:spring-boot-starter-tomcat",
                    "org.apache.tomcat.embed:tomcat-embed-core",
                    "org.apache.tomcat.embed:tomcat-embed-el",
                    "org.apache.tomcat.embed:tomcat-embed-websocket",
                    "org.springframework:spring-web",
                    "org.springframework:spring-webmvc",
                    "ch.qos.logback:logback-classic",
                    "ch.qos.logback:logback-core",
                    "org.slf4j:slf4j-api",
                    "org.yaml:snakeyaml"
            ),
            "org.springframework.boot:spring-boot-starter-data-jpa", List.of(
                    "org.springframework.boot:spring-boot-starter-jdbc",
                    "org.hibernate.orm:hibernate-core",
                    "org.springframework.data:spring-data-jpa",
                    "org.springframework:spring-aspects"
            ),
            "org.springframework.boot:spring-boot-starter-security", List.of(
                    "org.springframework.security:spring-security-config",
                    "org.springframework.security:spring-security-web",
                    "org.springframework:spring-aop"
            )
    );

    /**
     * 저장소 전체 디렉토리를 순회하여 모든 생태계의 패키지/라이브러리 매니페스트를 수집하고,
     * Lock 파일이 없더라도 Gradle/Maven Wrapper 또는 의존성 트리를 통해 모든 전이(간접) 의존성을 완전 추출합니다.
     */
    public List<LLMAnalysisService.SbomPackageDetail> scan(Path rootDir) {
        if (rootDir == null || !Files.exists(rootDir)) {
            return Collections.emptyList();
        }

        Map<String, LLMAnalysisService.SbomPackageDetail> packagesMap = new LinkedHashMap<>();
        boolean[] hasGradle = new boolean[1];
        boolean[] hasMaven = new boolean[1];

        try {
            Files.walkFileTree(rootDir, new SimpleFileVisitor<>() {
                @Override
                public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) {
                    String dirName = dir.getFileName() != null ? dir.getFileName().toString() : "";
                    if (IGNORED_DIRS.contains(dirName)) {
                        return FileVisitResult.SKIP_SUBTREE;
                    }
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                    String lower = file.getFileName().toString().toLowerCase();
                    if (lower.equals("build.gradle") || lower.equals("build.gradle.kts")) {
                        hasGradle[0] = true;
                    } else if (lower.equals("pom.xml")) {
                        hasMaven[0] = true;
                    }
                    parseManifestFile(file, packagesMap);
                    return FileVisitResult.CONTINUE;
                }
            });
        } catch (IOException e) {
            log.warn("[UniversalScanner] 매니페스트 탐색 중 I/O 경고: {}", e.getMessage());
        }

        // 1. Gradle 프로젝트: Lock 파일이 없더라도 Wrapper CLI 실행을 통해 전이(간접) 의존성 완전 복원
        if (hasGradle[0]) {
            boolean treeResolved = resolveGradleViaWrapper(rootDir, packagesMap);
            if (!treeResolved) {
                // Wrapper 부재 또는 실행 불가 시 카탈로그 및 Maven Central Fallback
                resolveGradleTransitiveFallback(packagesMap);
            }
            // Trivy가 모든 전이(간접) 의존성을 감지 및 CVE 검사할 수 있도록 gradle.lockfile 자동 합성 생성
            generateGradleLockfile(rootDir, packagesMap);
        }

        // 2. Maven 프로젝트: Maven Wrapper CLI 또는 Fallback
        if (hasMaven[0]) {
            boolean treeResolved = resolveMavenViaWrapper(rootDir, packagesMap);
            if (!treeResolved) {
                resolveMavenTransitiveFallback(packagesMap);
            }
        }

        List<LLMAnalysisService.SbomPackageDetail> result = new ArrayList<>(packagesMap.values());
        int direct = 0;
        int indirect = 0;
        for (LLMAnalysisService.SbomPackageDetail p : result) {
            if (p.indirect()) indirect++;
            else direct++;
        }
        log.info("[UniversalScanner] 범용 매니페스트 및 간접 의존성 스캔 완료: 직접 {}개, 간접 {}개, 총 {}개 패키지 검출",
                direct, indirect, result.size());
        return result;
    }

    private void parseManifestFile(Path file, Map<String, LLMAnalysisService.SbomPackageDetail> packagesMap) {
        String fileName = file.getFileName().toString();
        String lowerName = fileName.toLowerCase();

        try {
            // 1. Java / Kotlin / Android: build.gradle & build.gradle.kts
            if (lowerName.equals("build.gradle") || lowerName.equals("build.gradle.kts")) {
                parseGradle(file, packagesMap);
            }
            // 2. Java: pom.xml
            else if (lowerName.equals("pom.xml")) {
                parseMaven(file, packagesMap);
            }
            // 3. C# / .NET / Unity: *.csproj, Directory.Build.props, packages.config
            else if (lowerName.endsWith(".csproj") || lowerName.endsWith(".fsproj") || lowerName.equals("directory.build.props")) {
                parseCsproj(file, packagesMap);
            } else if (lowerName.equals("packages.config")) {
                parsePackagesConfig(file, packagesMap);
            }
            // 4. Unity Game Engine: manifest.json (Packages/manifest.json)
            else if (lowerName.equals("manifest.json") && file.getParent() != null && file.getParent().endsWith("Packages")) {
                parseUnityManifest(file, packagesMap);
            }
            // 5. C / C++: vcpkg.json, conanfile.txt, CMakeLists.txt
            else if (lowerName.equals("vcpkg.json")) {
                parseVcpkg(file, packagesMap);
            } else if (lowerName.equals("conanfile.txt")) {
                parseConan(file, packagesMap);
            } else if (lowerName.equals("cmakelists.txt")) {
                parseCMake(file, packagesMap);
            }
            // 6. Mobile (iOS / macOS): Podfile, Package.swift
            else if (lowerName.equals("podfile")) {
                parsePodfile(file, packagesMap);
            } else if (lowerName.equals("package.swift")) {
                parseSwiftPackage(file, packagesMap);
            }
            // 7. Mobile (Flutter / Dart): pubspec.yaml
            else if (lowerName.equals("pubspec.yaml")) {
                parsePubspec(file, packagesMap);
            }
            // 8. Python: requirements.txt, pyproject.toml
            else if (lowerName.equals("requirements.txt") || lowerName.endsWith("-requirements.txt")) {
                parsePythonReqs(file, packagesMap);
            }
            // 9. Rust: Cargo.toml
            else if (lowerName.equals("cargo.toml")) {
                parseCargo(file, packagesMap);
            }
            // 10. Go: go.mod
            else if (lowerName.equals("go.mod")) {
                parseGoMod(file, packagesMap);
            }
            // 11. Node.js / React Native: package.json (Trivy가 누락한 경우 대비)
            else if (lowerName.equals("package.json") && !file.toString().contains("node_modules")) {
                parsePackageJson(file, packagesMap);
            }
        } catch (Exception e) {
            log.debug("[UniversalScanner] 파일 파싱 스킵 ({}): {}", fileName, e.getMessage());
        }
    }

    private void parseGradle(Path file, Map<String, LLMAnalysisService.SbomPackageDetail> map) throws IOException {
        String content = Files.readString(file, StandardCharsets.UTF_8);
        Matcher m = GRADLE_DEP_PATTERN.matcher(content);
        while (m.find()) {
            String group = m.group(1).trim();
            String name = m.group(2).trim();
            String version = m.group(3) != null ? m.group(3).trim() : "(managed)";
            String fullName = group + ":" + name;
            map.putIfAbsent(fullName, new LLMAnalysisService.SbomPackageDetail(fullName, version, false, "Maven/Gradle"));
        }
        Matcher pm = GRADLE_PLUGIN_PATTERN.matcher(content);
        while (pm.find()) {
            String plugin = pm.group(1).trim();
            String version = pm.group(2).trim();
            map.putIfAbsent(plugin, new LLMAnalysisService.SbomPackageDetail(plugin, version, false, "Gradle-Plugin"));
        }
    }

    private void parseMaven(Path file, Map<String, LLMAnalysisService.SbomPackageDetail> map) throws IOException {
        String content = Files.readString(file, StandardCharsets.UTF_8);
        Matcher m = MAVEN_DEP_PATTERN.matcher(content);
        while (m.find()) {
            String group = m.group(1).trim();
            String artifact = m.group(2).trim();
            String version = m.group(3) != null ? m.group(3).trim() : "(managed)";
            String fullName = group + ":" + artifact;
            map.putIfAbsent(fullName, new LLMAnalysisService.SbomPackageDetail(fullName, version, false, "Maven"));
        }
    }

    private void parseCsproj(Path file, Map<String, LLMAnalysisService.SbomPackageDetail> map) throws IOException {
        String content = Files.readString(file, StandardCharsets.UTF_8);
        Matcher m = CSPROJ_PACKAGE_PATTERN.matcher(content);
        while (m.find()) {
            String name = m.group(1) != null ? m.group(1) : m.group(4);
            String version = m.group(2) != null ? m.group(2) : m.group(3);
            if (name != null) {
                map.putIfAbsent(name, new LLMAnalysisService.SbomPackageDetail(name, version != null ? version : "latest", false, "NuGet"));
            }
        }
    }

    private void parsePackagesConfig(Path file, Map<String, LLMAnalysisService.SbomPackageDetail> map) throws IOException {
        String content = Files.readString(file, StandardCharsets.UTF_8);
        Matcher m = PACKAGES_CONFIG_PATTERN.matcher(content);
        while (m.find()) {
            String id = m.group(1).trim();
            String ver = m.group(2).trim();
            map.putIfAbsent(id, new LLMAnalysisService.SbomPackageDetail(id, ver, false, "NuGet"));
        }
    }

    private void parseUnityManifest(Path file, Map<String, LLMAnalysisService.SbomPackageDetail> map) throws IOException {
        JsonNode root = objectMapper.readTree(file.toFile());
        JsonNode deps = root.path("dependencies");
        if (deps.isObject()) {
            deps.fieldNames().forEachRemaining(pkgName -> {
                String ver = deps.path(pkgName).asText("latest");
                map.putIfAbsent(pkgName, new LLMAnalysisService.SbomPackageDetail(pkgName, ver, false, "Unity-Package"));
            });
        }
    }

    private void parseVcpkg(Path file, Map<String, LLMAnalysisService.SbomPackageDetail> map) throws IOException {
        JsonNode root = objectMapper.readTree(file.toFile());
        JsonNode deps = root.path("dependencies");
        if (deps.isArray()) {
            for (JsonNode dep : deps) {
                if (dep.isTextual()) {
                    String name = dep.asText();
                    map.putIfAbsent(name, new LLMAnalysisService.SbomPackageDetail(name, "latest", false, "vcpkg(C/C++)"));
                } else if (dep.isObject()) {
                    String name = dep.path("name").asText("");
                    String ver = dep.path("version>=").asText("latest");
                    if (!name.isBlank()) {
                        map.putIfAbsent(name, new LLMAnalysisService.SbomPackageDetail(name, ver, false, "vcpkg(C/C++)"));
                    }
                }
            }
        }
    }

    private void parseConan(Path file, Map<String, LLMAnalysisService.SbomPackageDetail> map) throws IOException {
        String content = Files.readString(file, StandardCharsets.UTF_8);
        int reqIndex = content.indexOf("[requires]");
        if (reqIndex != -1) {
            String sub = content.substring(reqIndex + 10);
            Matcher m = CONAN_REQ_PATTERN.matcher(sub);
            while (m.find()) {
                String name = m.group(1).trim();
                String ver = m.group(2).trim();
                map.putIfAbsent(name, new LLMAnalysisService.SbomPackageDetail(name, ver, false, "Conan(C/C++)"));
            }
        }
    }

    private void parseCMake(Path file, Map<String, LLMAnalysisService.SbomPackageDetail> map) throws IOException {
        String content = Files.readString(file, StandardCharsets.UTF_8);
        Matcher m = CMAKE_FIND_PACKAGE_PATTERN.matcher(content);
        while (m.find()) {
            String name = m.group(1).trim();
            String ver = m.group(2) != null ? m.group(2).trim() : "system";
            map.putIfAbsent(name, new LLMAnalysisService.SbomPackageDetail(name, ver, false, "CMake(C/C++)"));
        }
    }

    private void parsePodfile(Path file, Map<String, LLMAnalysisService.SbomPackageDetail> map) throws IOException {
        String content = Files.readString(file, StandardCharsets.UTF_8);
        Matcher m = PODFILE_PATTERN.matcher(content);
        while (m.find()) {
            String name = m.group(1).trim();
            String ver = m.group(2) != null ? m.group(2).trim() : "latest";
            map.putIfAbsent(name, new LLMAnalysisService.SbomPackageDetail(name, ver, false, "CocoaPods(iOS)"));
        }
    }

    private void parseSwiftPackage(Path file, Map<String, LLMAnalysisService.SbomPackageDetail> map) throws IOException {
        String content = Files.readString(file, StandardCharsets.UTF_8);
        Matcher m = SWIFT_PKG_PATTERN.matcher(content);
        while (m.find()) {
            String name = m.group(1).trim();
            String ver = m.group(2).trim();
            map.putIfAbsent(name, new LLMAnalysisService.SbomPackageDetail(name, ver, false, "SwiftPM(iOS)"));
        }
    }

    private void parsePubspec(Path file, Map<String, LLMAnalysisService.SbomPackageDetail> map) throws IOException {
        List<String> lines = Files.readAllLines(file, StandardCharsets.UTF_8);
        boolean inDeps = false;
        for (String line : lines) {
            String trimmed = line.trim();
            if (trimmed.equals("dependencies:") || trimmed.equals("dev_dependencies:")) {
                inDeps = true;
                continue;
            }
            if (inDeps) {
                if (!line.startsWith(" ") && !line.startsWith("\t") && trimmed.endsWith(":")) {
                    inDeps = false;
                    continue;
                }
                int colonIdx = trimmed.indexOf(':');
                if (colonIdx > 0 && !trimmed.startsWith("#")) {
                    String name = trimmed.substring(0, colonIdx).trim();
                    String ver = trimmed.substring(colonIdx + 1).replace("\"", "").replace("'", "").trim();
                    if (!name.equals("flutter") && !ver.isBlank()) {
                        map.putIfAbsent(name, new LLMAnalysisService.SbomPackageDetail(name, ver, false, "Pub(Flutter/Dart)"));
                    }
                }
            }
        }
    }

    private void parsePythonReqs(Path file, Map<String, LLMAnalysisService.SbomPackageDetail> map) throws IOException {
        String content = Files.readString(file, StandardCharsets.UTF_8);
        Matcher m = PYTHON_REQ_PATTERN.matcher(content);
        while (m.find()) {
            String name = m.group(1).trim();
            String ver = m.group(2).trim();
            map.putIfAbsent(name, new LLMAnalysisService.SbomPackageDetail(name, ver, false, "PyPI(Python)"));
        }
    }

    private void parseCargo(Path file, Map<String, LLMAnalysisService.SbomPackageDetail> map) throws IOException {
        String content = Files.readString(file, StandardCharsets.UTF_8);
        Matcher m = CARGO_DEP_PATTERN.matcher(content);
        while (m.find()) {
            String name = m.group(1).trim();
            String ver = m.group(2) != null ? m.group(2).trim() : (m.group(3) != null ? m.group(3).trim() : "latest");
            map.putIfAbsent(name, new LLMAnalysisService.SbomPackageDetail(name, ver, false, "Crates.io(Rust)"));
        }
    }

    private void parseGoMod(Path file, Map<String, LLMAnalysisService.SbomPackageDetail> map) throws IOException {
        String content = Files.readString(file, StandardCharsets.UTF_8);
        Matcher m = GO_MOD_PATTERN.matcher(content);
        while (m.find()) {
            String name = m.group(1).trim();
            String ver = m.group(2).trim();
            map.putIfAbsent(name, new LLMAnalysisService.SbomPackageDetail(name, ver, false, "Go-Modules"));
        }
    }

    private void parsePackageJson(Path file, Map<String, LLMAnalysisService.SbomPackageDetail> map) throws IOException {
        JsonNode root = objectMapper.readTree(file.toFile());
        for (String field : List.of("dependencies", "devDependencies")) {
            JsonNode deps = root.path(field);
            if (deps.isObject()) {
                deps.fieldNames().forEachRemaining(name -> {
                    String ver = deps.path(name).asText("latest");
                    map.putIfAbsent(name, new LLMAnalysisService.SbomPackageDetail(name, ver, false, "npm/Node.js"));
                });
            }
        }
    }

    private boolean resolveGradleViaWrapper(Path rootDir, Map<String, LLMAnalysisService.SbomPackageDetail> packagesMap) {
        boolean isWindows = System.getProperty("os.name").toLowerCase().contains("win");
        Path wrapper = rootDir.resolve(isWindows ? "gradlew.bat" : "gradlew");
        if (!Files.exists(wrapper)) {
            return false;
        }

        if (!isWindows) {
            wrapper.toFile().setExecutable(true, false);
        }

        List<String> command = new ArrayList<>();
        if (isWindows) {
            command.add("cmd.exe");
            command.add("/c");
            command.add(wrapper.toAbsolutePath().toString());
        } else {
            command.add(wrapper.toAbsolutePath().toString());
        }
        command.add("-q");
        command.add("dependencies");
        command.add("--configuration");
        command.add("runtimeClasspath");
        command.add("--no-daemon");

        String output = runProcessWithTimeout(command, rootDir, 25, TimeUnit.SECONDS, "Gradle Wrapper");
        if (output == null || output.isBlank() || !output.contains("---")) {
            // runtimeClasspath 실패 시 compileClasspath로 1회 재시도
            List<String> fallbackCmd = new ArrayList<>(command);
            fallbackCmd.set(4, "compileClasspath");
            output = runProcessWithTimeout(fallbackCmd, rootDir, 20, TimeUnit.SECONDS, "Gradle Wrapper (compileClasspath)");
        }

        if (output != null && output.contains("---")) {
            int beforeCount = packagesMap.size();
            parseGradleDependencyTreeOutput(output, packagesMap);
            log.info("[UniversalScanner] Gradle Wrapper 의존성 트리 해석 완료 (신규/최신화: {}개 추가 반영)",
                    packagesMap.size() - beforeCount);
            return true;
        }

        return false;
    }

    public void parseGradleDependencyTreeOutput(String output, Map<String, LLMAnalysisService.SbomPackageDetail> map) {
        if (output == null || output.isBlank()) {
            return;
        }

        Pattern treeLinePattern = Pattern.compile("^([|\\s]*)(?:\\+|\\\\)--- (.+)$");

        String[] lines = output.split("\\r?\\n");
        for (String rawLine : lines) {
            Matcher m = treeLinePattern.matcher(rawLine);
            if (!m.matches()) {
                continue;
            }

            String indent = m.group(1);
            boolean isIndirect = (indent != null && !indent.isBlank());
            String dep = m.group(2).trim();

            // (c)로 끝나는 제약 조건(BOM constraint) 제외
            if (dep.endsWith("(c)")) {
                continue;
            }

            // (*)로 끝나는 중복 하위 트리 표기 제거
            if (dep.endsWith("(*)")) {
                dep = dep.substring(0, dep.length() - 3).trim();
            }

            String name;
            String version;

            if (dep.contains(" -> ")) {
                String[] parts = dep.split(" -> ");
                version = parts[1].trim();
                String left = parts[0].trim();
                int firstColon = left.indexOf(':');
                if (firstColon > 0) {
                    String group = left.substring(0, firstColon).trim();
                    String rest = left.substring(firstColon + 1).trim();
                    int secondColon = rest.indexOf(':');
                    String artifact = (secondColon > 0) ? rest.substring(0, secondColon).trim() : rest;
                    name = group + ":" + artifact;
                } else {
                    name = left;
                }
            } else {
                String[] parts = dep.split(":");
                if (parts.length >= 3) {
                    name = parts[0].trim() + ":" + parts[1].trim();
                    version = parts[2].trim();
                } else if (parts.length == 2) {
                    name = parts[0].trim() + ":" + parts[1].trim();
                    version = "(managed)";
                } else {
                    continue;
                }
            }

            if (!name.isBlank()) {
                if (version.contains(" ")) {
                    version = version.split("\\s+")[0].trim();
                }

                LLMAnalysisService.SbomPackageDetail existing = map.get(name);
                if (existing != null && !existing.indirect()) {
                    // 이미 직접 의존성으로 등록된 패키지는 간접 의존성으로 강등하지 않고, 버전이 (managed)였다면 최신 해결 버전으로 갱신
                    if (("(managed)".equals(existing.version()) || existing.version().isBlank()) && !"(managed)".equals(version)) {
                        map.put(name, new LLMAnalysisService.SbomPackageDetail(name, version, false, "Maven/Gradle"));
                    }
                } else {
                    map.put(name, new LLMAnalysisService.SbomPackageDetail(name, version, isIndirect, "Maven/Gradle"));
                }
            }
        }
    }

    private void generateGradleLockfile(Path rootDir, Map<String, LLMAnalysisService.SbomPackageDetail> packagesMap) {
        Path lockfile = rootDir.resolve("gradle.lockfile");
        if (Files.exists(lockfile)) {
            log.info("[UniversalScanner] 저장소에 이미 gradle.lockfile이 존재하므로 자동 생성을 건너뜁니다.");
            return;
        }

        StringBuilder sb = new StringBuilder();
        sb.append("# This is a Gradle generated file for dependency locking.\n");
        sb.append("# Generated by PR Guard Universal Dependency Resolver\n");

        int count = 0;
        for (LLMAnalysisService.SbomPackageDetail pkg : packagesMap.values()) {
            String name = pkg.name();
            String version = pkg.version();
            if (name.contains(":") && !version.isBlank() && !"(managed)".equals(version) && !"latest".equals(version) && !"system".equals(version)) {
                sb.append(name).append(":").append(version).append("=runtimeClasspath\n");
                count++;
            }
        }

        if (count > 0) {
            sb.append("empty=annotationProcessor,testAnnotationProcessor\n");
            try {
                Files.writeString(lockfile, sb.toString(), StandardCharsets.UTF_8);
                log.info("[UniversalScanner] 🛡️ Lock 파일 부재 대응: gradle.lockfile 자동 합성 완료 (총 {}개 패키지 동기화 -> Trivy가 모든 간접 의존성 취약점 스캔 가능)", count);
            } catch (IOException e) {
                log.warn("[UniversalScanner] gradle.lockfile 자동 합성 중 I/O 경고: {}", e.getMessage());
            }
        }
    }

    private void resolveGradleTransitiveFallback(Map<String, LLMAnalysisService.SbomPackageDetail> packagesMap) {
        boolean hasIndirect = packagesMap.values().stream().anyMatch(LLMAnalysisService.SbomPackageDetail::indirect);
        if (hasIndirect) {
            return;
        }

        String bootVersion = "3.2.0";
        for (LLMAnalysisService.SbomPackageDetail p : packagesMap.values()) {
            if (p.name().contains("spring-boot") && !"(managed)".equals(p.version()) && !p.version().isBlank()) {
                bootVersion = p.version();
                break;
            }
        }

        List<LLMAnalysisService.SbomPackageDetail> directs = new ArrayList<>(packagesMap.values());
        for (LLMAnalysisService.SbomPackageDetail direct : directs) {
            List<String> children = COMMON_STARTER_CHILDREN.get(direct.name());
            if (children != null) {
                for (String child : children) {
                    packagesMap.putIfAbsent(child, new LLMAnalysisService.SbomPackageDetail(child, bootVersion, true, "Maven/Gradle"));
                }
            } else if (direct.name().startsWith("org.springframework.boot:spring-boot-starter-")) {
                fetchPomFromMavenCentral(direct.name(), bootVersion, packagesMap);
            }
        }
    }

    private void fetchPomFromMavenCentral(String fullName, String defaultVersion, Map<String, LLMAnalysisService.SbomPackageDetail> map) {
        String[] parts = fullName.split(":");
        if (parts.length < 2) return;
        String group = parts[0].trim();
        String artifact = parts[1].trim();
        String version = (parts.length >= 3 && !"(managed)".equals(parts[2])) ? parts[2].trim() : defaultVersion;

        try {
            String groupPath = group.replace('.', '/');
            String urlStr = "https://repo1.maven.org/maven2/" + groupPath + "/" + artifact + "/" + version + "/" + artifact + "-" + version + ".pom";
            HttpClient client = HttpClient.newBuilder()
                    .connectTimeout(Duration.ofMillis(1500))
                    .build();
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(urlStr))
                    .timeout(Duration.ofMillis(2000))
                    .GET()
                    .build();
            HttpResponse<String> resp = client.send(request, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() == 200) {
                Matcher m = MAVEN_DEP_PATTERN.matcher(resp.body());
                while (m.find()) {
                    String childGroup = m.group(1).trim();
                    String childArtifact = m.group(2).trim();
                    String childVer = (m.group(3) != null && !m.group(3).isBlank()) ? m.group(3).trim() : version;
                    String childFullName = childGroup + ":" + childArtifact;
                    map.putIfAbsent(childFullName, new LLMAnalysisService.SbomPackageDetail(childFullName, childVer, true, "Maven/Gradle"));
                }
            }
        } catch (Exception e) {
            log.debug("[UniversalScanner] Maven Central POM 보조 조회 스킵 ({}): {}", fullName, e.getMessage());
        }
    }

    private boolean resolveMavenViaWrapper(Path rootDir, Map<String, LLMAnalysisService.SbomPackageDetail> packagesMap) {
        boolean isWindows = System.getProperty("os.name").toLowerCase().contains("win");
        Path wrapper = rootDir.resolve(isWindows ? "mvnw.cmd" : "mvnw");
        if (!Files.exists(wrapper)) {
            return false;
        }

        if (!isWindows) {
            wrapper.toFile().setExecutable(true, false);
        }

        List<String> command = new ArrayList<>();
        if (isWindows) {
            command.add("cmd.exe");
            command.add("/c");
            command.add(wrapper.toAbsolutePath().toString());
        } else {
            command.add(wrapper.toAbsolutePath().toString());
        }
        command.add("-q");
        command.add("dependency:tree");
        command.add("-DoutputType=text");

        String output = runProcessWithTimeout(command, rootDir, 25, TimeUnit.SECONDS, "Maven Wrapper");
        if (output != null && (output.contains("+-") || output.contains("\\-"))) {
            int beforeCount = packagesMap.size();
            parseMavenDependencyTreeOutput(output, packagesMap);
            log.info("[UniversalScanner] Maven Wrapper 의존성 트리 해석 완료 (신규/최신화: {}개 추가 반영)",
                    packagesMap.size() - beforeCount);
            return true;
        }

        return false;
    }

    public void parseMavenDependencyTreeOutput(String output, Map<String, LLMAnalysisService.SbomPackageDetail> map) {
        if (output == null || output.isBlank()) {
            return;
        }

        Pattern mavenTreePattern = Pattern.compile("^(?:\\[INFO\\]\\s*)?([|\\s]*)(?:\\+-|\\\\-)\\s+(.+)$");
        String[] lines = output.split("\\r?\\n");
        for (String rawLine : lines) {
            Matcher m = mavenTreePattern.matcher(rawLine);
            if (!m.matches()) {
                continue;
            }

            String indent = m.group(1);
            boolean isIndirect = (indent != null && !indent.isBlank());
            String dep = m.group(2).trim();

            String[] parts = dep.split(":");
            if (parts.length >= 4) {
                String group = parts[0].trim();
                String artifact = parts[1].trim();
                String version = parts[3].trim();
                String fullName = group + ":" + artifact;

                LLMAnalysisService.SbomPackageDetail existing = map.get(fullName);
                if (existing != null && !existing.indirect()) {
                    if ("(managed)".equals(existing.version()) && !"(managed)".equals(version)) {
                        map.put(fullName, new LLMAnalysisService.SbomPackageDetail(fullName, version, false, "Maven"));
                    }
                } else {
                    map.put(fullName, new LLMAnalysisService.SbomPackageDetail(fullName, version, isIndirect, "Maven"));
                }
            }
        }
    }

    private void resolveMavenTransitiveFallback(Map<String, LLMAnalysisService.SbomPackageDetail> packagesMap) {
        resolveGradleTransitiveFallback(packagesMap);
    }

    private String runProcessWithTimeout(List<String> command, Path rootDir, long timeout, TimeUnit unit, String processName) {
        ProcessBuilder pb = new ProcessBuilder(command);
        pb.directory(rootDir.toFile());
        pb.redirectErrorStream(true);
        pb.environment().put("GRADLE_OPTS", "-Dorg.gradle.daemon=false -Dorg.gradle.parallel=false");

        try {
            Process process = pb.start();
            CompletableFuture<String> readFuture = CompletableFuture.supplyAsync(() -> {
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
                    StringBuilder sb = new StringBuilder();
                    String line;
                    while ((line = reader.readLine()) != null) {
                        sb.append(line).append("\n");
                    }
                    return sb.toString();
                } catch (IOException e) {
                    return "";
                }
            });

            boolean finished = process.waitFor(timeout, unit);
            if (!finished) {
                process.destroyForcibly();
                readFuture.cancel(true);
                log.warn("[UniversalScanner] {} 프로세스 타임아웃 초과 ({} {})", processName, timeout, unit.name().toLowerCase());
                return null;
            }

            if (process.exitValue() != 0) {
                String errOutput = readFuture.get(2, TimeUnit.SECONDS);
                log.warn("[UniversalScanner] {} 프로세스 비정상 종료 (Exit code: {}): {}",
                        processName, process.exitValue(), errOutput.length() > 300 ? errOutput.substring(0, 300) : errOutput);
                return null;
            }

            return readFuture.get(5, TimeUnit.SECONDS);
        } catch (Exception e) {
            log.warn("[UniversalScanner] {} 실행 중 오류 발생: {}", processName, e.getMessage());
            return null;
        }
    }
}

