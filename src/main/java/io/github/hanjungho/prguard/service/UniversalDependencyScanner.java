package io.github.hanjungho.prguard.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
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

    /**
     * 저장소 전체 디렉토리를 순회하여 모든 생태계의 패키지/라이브러리 매니페스트를 수집합니다.
     */
    public List<LLMAnalysisService.SbomPackageDetail> scan(Path rootDir) {
        if (rootDir == null || !Files.exists(rootDir)) {
            return Collections.emptyList();
        }

        Map<String, LLMAnalysisService.SbomPackageDetail> packagesMap = new LinkedHashMap<>();

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
                    parseManifestFile(file, packagesMap);
                    return FileVisitResult.CONTINUE;
                }
            });
        } catch (IOException e) {
            log.warn("[UniversalScanner] 매니페스트 탐색 중 I/O 경고: {}", e.getMessage());
        }

        List<LLMAnalysisService.SbomPackageDetail> result = new ArrayList<>(packagesMap.values());
        log.info("[UniversalScanner] 범용 매니페스트 스캔 완료: 총 {}개 패키지 직접 검출", result.size());
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
}
