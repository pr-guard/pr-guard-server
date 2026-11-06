package io.github.hanjungho.prguard.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 프로젝트 내 실제 존재하는 매니페스트 및 Lock 파일을 직접 탐색하고 파싱하는 범용 SBOM 추출기.
 * 가짜 목(Mock) 데이터나 임의의 합성 파일 생성 없이, 오직 실제 저장소 코드에 선언된 의존성만을 동적으로 추출합니다.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class UniversalDependencyScanner {

    private final ObjectMapper objectMapper;

    @org.springframework.beans.factory.annotation.Value("${scanner.wrapper.enabled:true}")
    private boolean wrapperExecutionEnabled = true;

    /**
     * 프로젝트 기본 사용 언어, 빌드 도구 및 주요 프레임워크 환경 메타데이터
     */
    public record ProjectEnvironment(
            String language,
            String buildTool,
            String framework
    ) {
        public static ProjectEnvironment unknown() {
            return new ProjectEnvironment("알 수 없음", "미지정", "미지정");
        }

        public String toSummaryString() {
            if (language != null && language.contains(" + ")) {
                return language;
            }
            StringBuilder sb = new StringBuilder();
            if (language != null && !language.isBlank() && !"알 수 없음".equals(language)) {
                sb.append(language);
            }
            if (buildTool != null && !buildTool.isBlank() && !"미지정".equals(buildTool)) {
                sb.append(" (").append(buildTool).append(")");
            }
            if (framework != null && !framework.isBlank() && !"미지정".equals(framework)) {
                sb.append(" / ").append(framework);
            }
            return sb.isEmpty() ? "기타/다중 언어 프로젝트" : sb.toString();
        }
    }

    private static final Set<String> IGNORED_DIRS = Set.of(
            ".git", ".gradle", ".idea", "node_modules", "target", "build", "bin", "obj",
            ".vs", ".vscode", "vendor", "dist", "out", ".next", ".nuxt",
            "venv", ".venv", "env", ".env", "__pycache__", ".pytest_cache", ".mypy_cache",
            ".tox", "Pods"
    );

    // Gradle Regex
    private static final Pattern GRADLE_DEP_PATTERN = Pattern.compile(
            "(?:implementation|api|compileOnly|runtimeOnly|testImplementation|testCompileOnly)\\s*[(]?['\"]([^:'\"\\s]+):([^:'\"\\s]+)(?::([^:'\"\\s]+))?['\"][)]?"
    );
    private static final Pattern GRADLE_PLUGIN_PATTERN = Pattern.compile(
            "id\\s*[(]?['\"]([^'\"\\s]+)['\"][)]?\\s+version\\s+['\"]([^'\"\\s]+)['\"]"
    );

    // Maven Regex
    private static final Pattern MAVEN_DEP_PATTERN = Pattern.compile(
            "<dependency>\\s*<groupId>([^<]+)</groupId>\\s*<artifactId>([^<]+)</artifactId>(?:\\s*<version>([^<]+)</version>)?",
            Pattern.DOTALL
    );
    private static final Pattern MAVEN_PARENT_PATTERN = Pattern.compile(
            "<parent>\\s*<groupId>([^<]+)</groupId>\\s*<artifactId>([^<]+)</artifactId>\\s*<version>([^<]+)</version>",
            Pattern.DOTALL
    );

    // Java Version Regex (Gradle / Maven)
    private static final Pattern GRADLE_JAVA_VERSION_PATTERN = Pattern.compile(
            "(?:JavaLanguageVersion\\.of\\((\\d+)\\)|jvmToolchain\\((\\d+)\\)|(?:sourceCompatibility|targetCompatibility)\\s*=\\s*['\"]?(?:1\\.)?(\\d+)['\"]?|VERSION_1_(\\d+)|VERSION_(\\d+))"
    );
    private static final Pattern MAVEN_JAVA_VERSION_PATTERN = Pattern.compile(
            "<(?:java\\.version|maven\\.compiler\\.source|maven\\.compiler\\.release|maven\\.compiler\\.target)>(?:1\\.)?(\\d+)</"
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
     * 저장소 디렉토리를 순회하여 실제 존재하는 매니페스트 및 Lock 파일의 패키지만 파싱합니다.
     * 디스크에 임의의 가짜 파일을 생성하거나 목(Mock) 데이터를 주입하지 않습니다.
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
                    if (IGNORED_DIRS.contains(dirName) || dirName.startsWith(".")) {
                        if (!dirName.equals(".")) {
                            return FileVisitResult.SKIP_SUBTREE;
                        }
                    }
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                    String fileName = file.getFileName().toString().toLowerCase();
                    if (fileName.equals("build.gradle") || fileName.equals("build.gradle.kts")) {
                        hasGradle[0] = true;
                    } else if (fileName.equals("pom.xml")) {
                        hasMaven[0] = true;
                    }
                    parseManifestFile(file, packagesMap);
                    return FileVisitResult.CONTINUE;
                }
            });
        } catch (IOException e) {
            log.warn("[UniversalScanner] 매니페스트 탐색 중 I/O 경고: {}", e.getMessage());
        }

        // 사용자가 명시적으로 Wrapper 실행을 허용한 경우에만 실제 Gradle/Maven CLI 트리 보강
        if (hasGradle[0] && wrapperExecutionEnabled) {
            resolveGradleViaWrapper(rootDir, packagesMap);
        }
        if (hasMaven[0] && wrapperExecutionEnabled) {
            resolveMavenViaWrapper(rootDir, packagesMap);
        }

        List<LLMAnalysisService.SbomPackageDetail> result = new ArrayList<>(packagesMap.values());
        int direct = 0;
        int indirect = 0;
        for (LLMAnalysisService.SbomPackageDetail p : result) {
            if (p.indirect()) indirect++;
            else direct++;
        }
        log.info("[UniversalScanner] 실제 저장소 매니페스트 스캔 완료: 직접 {}개, 간접 {}개, 총 {}개 패키지 검출",
                direct, indirect, result.size());
        return result;
    }

    /**
     * 저장소 내 실제 매니페스트 파일 및 패키지 구성을 바탕으로 기본 프로그래밍 언어, 빌드 툴, 프레임워크를 동적으로 식별합니다.
     */
    public ProjectEnvironment detectProjectEnvironment(Path rootDir, List<LLMAnalysisService.SbomPackageDetail> packages) {
        if (rootDir == null || !Files.exists(rootDir)) {
            return ProjectEnvironment.unknown();
        }

        List<LLMAnalysisService.SbomPackageDetail> safePackages = (packages != null) ? packages : Collections.emptyList();
        List<ProjectEnvironment> detectedList = new ArrayList<>();

        // 1. Java / Kotlin (JVM)
        boolean hasGradleKts = hasFile(rootDir, "build.gradle.kts");
        boolean hasGradle = hasFile(rootDir, "build.gradle") || hasGradleKts;
        boolean hasMaven = hasFile(rootDir, "pom.xml");
        boolean hasJvmPackages = safePackages.stream().anyMatch(p -> {
            String lic = p.license() != null ? p.license().toLowerCase() : "";
            return lic.contains("maven") || lic.contains("gradle") || p.name().contains(":");
        });

        if (hasGradle || hasMaven || hasJvmPackages) {
            String javaVersion = null;
            if (hasGradle) {
                Path gFile = hasGradleKts ? resolveFilePath(rootDir, "build.gradle.kts") : resolveFilePath(rootDir, "build.gradle");
                if (gFile != null && Files.exists(gFile)) {
                    try {
                        String gContent = Files.readString(gFile, StandardCharsets.UTF_8);
                        Matcher jm = GRADLE_JAVA_VERSION_PATTERN.matcher(gContent);
                        if (jm.find()) {
                            for (int i = 1; i <= jm.groupCount(); i++) {
                                if (jm.group(i) != null) {
                                    javaVersion = jm.group(i);
                                    break;
                                }
                            }
                        }
                    } catch (Exception ignored) {}
                }
            } else if (hasMaven) {
                Path mFile = resolveFilePath(rootDir, "pom.xml");
                if (mFile != null && Files.exists(mFile)) {
                    try {
                        String mContent = Files.readString(mFile, StandardCharsets.UTF_8);
                        Matcher jm = MAVEN_JAVA_VERSION_PATTERN.matcher(mContent);
                        if (jm.find()) {
                            javaVersion = jm.group(1);
                        }
                    } catch (Exception ignored) {}
                }
            }

            String langSuffix = (javaVersion != null && !javaVersion.isBlank()) ? " " + javaVersion : "";
            String language = hasGradleKts ? ("Kotlin / Java" + langSuffix) : ("Java" + langSuffix);
            String buildTool = hasGradle ? "Gradle" : (hasMaven ? "Maven" : "Gradle/Maven");
            String framework = "미지정";

            for (LLMAnalysisService.SbomPackageDetail p : safePackages) {
                if (p.name().contains("spring-boot")) {
                    String ver = (p.version() != null && !p.version().isBlank() && !"(managed)".equals(p.version()))
                            ? " " + p.version().trim()
                            : "";
                    framework = "Spring Boot" + ver;
                    break;
                } else if (p.name().contains("quarkus")) {
                    framework = "Quarkus";
                    break;
                } else if (p.name().contains("micronaut")) {
                    framework = "Micronaut";
                    break;
                }
            }
            detectedList.add(new ProjectEnvironment(language, buildTool, framework));
        }

        // 2. Node.js (JavaScript / TypeScript)
        boolean hasPackageJson = hasFile(rootDir, "package.json");
        boolean hasNodePackages = safePackages.stream().anyMatch(p -> {
            String lic = p.license() != null ? p.license().toLowerCase() : "";
            return lic.contains("npm") || lic.contains("yarn") || lic.contains("pnpm") || lic.contains("node");
        });

        if (hasPackageJson || hasNodePackages) {
            boolean isTs = hasFile(rootDir, "tsconfig.json") || hasFileExtension(rootDir, ".ts") || hasFileExtension(rootDir, ".tsx");
            String language = isTs ? "TypeScript" : "JavaScript";
            String buildTool;
            if (hasFile(rootDir, "pnpm-lock.yaml")) buildTool = "pnpm";
            else if (hasFile(rootDir, "yarn.lock")) buildTool = "Yarn";
            else if (hasFile(rootDir, "package-lock.json")) buildTool = "npm";
            else buildTool = "npm";

            String framework = "Node.js";
            for (LLMAnalysisService.SbomPackageDetail p : safePackages) {
                String n = p.name().toLowerCase();
                if (n.equals("next")) { framework = "Next.js"; break; }
                if (n.equals("react") || n.equals("react-dom")) { framework = "React"; break; }
                if (n.equals("vue")) { framework = "Vue.js"; break; }
                if (n.equals("express")) { framework = "Express"; break; }
                if (n.equals("@nestjs/core")) { framework = "NestJS"; break; }
            }
            detectedList.add(new ProjectEnvironment(language, buildTool, framework));
        }

        // 3. Python
        boolean hasPythonManifest = hasFile(rootDir, "requirements.txt") || hasFile(rootDir, "pyproject.toml")
                || hasFile(rootDir, "Pipfile") || hasFile(rootDir, "setup.py") || hasFile(rootDir, "setup.cfg");
        boolean hasPythonPackages = safePackages.stream().anyMatch(p -> {
            String lic = p.license() != null ? p.license().toLowerCase() : "";
            return lic.contains("pypi") || lic.contains("python") || lic.contains("poetry") || lic.contains("pip");
        });

        if (hasPythonManifest || hasPythonPackages) {
            String buildTool;
            if (hasFile(rootDir, "poetry.lock")) buildTool = "Poetry";
            else if (hasFile(rootDir, "Pipfile.lock")) buildTool = "Pipenv";
            else buildTool = "pip";

            String framework = "미지정";
            for (LLMAnalysisService.SbomPackageDetail p : safePackages) {
                String n = p.name().toLowerCase();
                if (n.equals("django")) { framework = "Django"; break; }
                if (n.equals("fastapi")) { framework = "FastAPI"; break; }
                if (n.equals("flask")) { framework = "Flask"; break; }
            }
            detectedList.add(new ProjectEnvironment("Python", buildTool, framework));
        }

        // 4. Rust
        if (hasFile(rootDir, "Cargo.toml") || safePackages.stream().anyMatch(p -> p.license() != null && p.license().toLowerCase().contains("cargo"))) {
            String framework = "미지정";
            for (LLMAnalysisService.SbomPackageDetail p : safePackages) {
                String n = p.name().toLowerCase();
                if (n.equals("actix-web")) { framework = "Actix Web"; break; }
                if (n.equals("axum")) { framework = "Axum"; break; }
                if (n.equals("tokio")) { framework = "Tokio"; break; }
            }
            detectedList.add(new ProjectEnvironment("Rust", "Cargo", framework));
        }

        // 5. Go
        if (hasFile(rootDir, "go.mod") || safePackages.stream().anyMatch(p -> p.license() != null && p.license().toLowerCase().contains("go"))) {
            String framework = "미지정";
            for (LLMAnalysisService.SbomPackageDetail p : safePackages) {
                String n = p.name().toLowerCase();
                if (n.contains("gin-gonic/gin")) { framework = "Gin"; break; }
                if (n.contains("labstack/echo")) { framework = "Echo"; break; }
                if (n.contains("gofiber/fiber")) { framework = "Fiber"; break; }
            }
            detectedList.add(new ProjectEnvironment("Go", "Go Modules", framework));
        }

        // 6. C# / .NET
        boolean hasCsproj = hasFileWithExtension(rootDir, ".csproj") || hasFileWithExtension(rootDir, ".fsproj");
        if (hasCsproj || safePackages.stream().anyMatch(p -> p.license() != null && p.license().toLowerCase().contains("nuget"))) {
            detectedList.add(new ProjectEnvironment("C# (.NET)", "NuGet / MSBuild", "ASP.NET Core / .NET"));
        }

        // 7. C / C++
        if (hasFile(rootDir, "CMakeLists.txt") || hasFile(rootDir, "conanfile.txt") || hasFile(rootDir, "vcpkg.json")) {
            String buildTool = hasFile(rootDir, "CMakeLists.txt") ? "CMake" : (hasFile(rootDir, "conanfile.txt") ? "Conan" : "vcpkg");
            detectedList.add(new ProjectEnvironment("C / C++", buildTool, "Native"));
        }

        // 8. Mobile
        if (hasFile(rootDir, "pubspec.yaml")) {
            detectedList.add(new ProjectEnvironment("Dart", "Flutter / pub", "Flutter"));
        }
        if (hasFile(rootDir, "Podfile") || hasFile(rootDir, "Package.swift")) {
            detectedList.add(new ProjectEnvironment("Swift", "SPM / CocoaPods", "iOS / Apple"));
        }

        // 단일 스택 감지 시 해당 단일 환경 반환
        if (detectedList.size() == 1) {
            return detectedList.get(0);
        }

        // 다중 스택(Polyglot) 감지 시: 개별 스택 요약을 " + "로 연결하여 복합 환경 생성
        if (detectedList.size() > 1) {
            String composite = detectedList.stream()
                    .map(ProjectEnvironment::toSummaryString)
                    .distinct()
                    .reduce((a, b) -> a + " + " + b)
                    .orElse("기타/다중 언어 프로젝트");
            return new ProjectEnvironment(composite, "다중 빌드 도구", "다중 프레임워크");
        }

        return ProjectEnvironment.unknown();
    }

    private boolean hasFile(Path rootDir, String fileName) {
        if (rootDir == null || !Files.exists(rootDir)) return false;
        if (Files.exists(rootDir.resolve(fileName))) return true;
        try (var s = Files.walk(rootDir, 3)) {
            return s.anyMatch(p -> p.getFileName() != null && p.getFileName().toString().equalsIgnoreCase(fileName));
        } catch (Exception e) {
            return false;
        }
    }

    private Path resolveFilePath(Path rootDir, String fileName) {
        if (rootDir == null || !Files.exists(rootDir)) return null;
        Path direct = rootDir.resolve(fileName);
        if (Files.exists(direct)) return direct;
        try (var s = Files.walk(rootDir, 3)) {
            return s.filter(p -> p.getFileName() != null && p.getFileName().toString().equalsIgnoreCase(fileName))
                    .findFirst()
                    .orElse(null);
        } catch (Exception e) {
            return null;
        }
    }

    private boolean hasFileWithExtension(Path rootDir, String ext) {
        if (rootDir == null || !Files.exists(rootDir)) return false;
        try (var s = Files.walk(rootDir, 3)) {
            return s.anyMatch(p -> p.getFileName() != null && p.getFileName().toString().toLowerCase().endsWith(ext));
        } catch (Exception e) {
            return false;
        }
    }

    private boolean hasFileExtension(Path rootDir, String ext) {
        if (rootDir == null || !Files.exists(rootDir)) return false;
        try (var stream = Files.walk(rootDir, 3)) {
            return stream.anyMatch(p -> p.getFileName() != null && p.getFileName().toString().toLowerCase().endsWith(ext));
        } catch (Exception e) {
            return false;
        }
    }

    private void parseManifestFile(Path file, Map<String, LLMAnalysisService.SbomPackageDetail> packagesMap) {
        String fileName = file.getFileName().toString();
        String lowerName = fileName.toLowerCase();

        try {
            // 1. Java / Kotlin / Android: build.gradle & build.gradle.kts & gradle.lockfile
            if (lowerName.equals("build.gradle") || lowerName.equals("build.gradle.kts")) {
                parseGradle(file, packagesMap);
            } else if (lowerName.equals("gradle.lockfile")) {
                parseGradleLockfile(file, packagesMap);
            }
            // 2. Java: pom.xml
            else if (lowerName.equals("pom.xml")) {
                parseMaven(file, packagesMap);
            }
            // 3. Node.js: package.json & package-lock.json & yarn.lock & pnpm-lock.yaml
            else if (lowerName.equals("package.json") && !file.toString().contains("node_modules")) {
                parsePackageJson(file, packagesMap);
            } else if (lowerName.equals("package-lock.json") && !file.toString().contains("node_modules")) {
                parsePackageLockJson(file, packagesMap);
            } else if (lowerName.equals("yarn.lock") && !file.toString().contains("node_modules")) {
                parseYarnLock(file, packagesMap);
            } else if (lowerName.equals("pnpm-lock.yaml") && !file.toString().contains("node_modules")) {
                parsePnpmLock(file, packagesMap);
            }
            // 4. Python: requirements*.txt, requirements*.in, pyproject.toml, Pipfile, poetry.lock, Pipfile.lock, setup.py, setup.cfg
            else if ((lowerName.contains("requirements") || isInsideRequirementsDir(file)) && (lowerName.endsWith(".txt") || lowerName.endsWith(".in"))) {
                parsePythonReqs(file, packagesMap);
            } else if (lowerName.equals("setup.py") || lowerName.equals("setup.cfg")) {
                parsePythonSetup(file, packagesMap);
            } else if (lowerName.equals("pyproject.toml")) {
                parsePyprojectToml(file, packagesMap);
            } else if (lowerName.equals("pipfile")) {
                parsePipfile(file, packagesMap);
            } else if (lowerName.equals("poetry.lock")) {
                parsePoetryLock(file, packagesMap);
            } else if (lowerName.equals("pipfile.lock")) {
                parsePipfileLock(file, packagesMap);
            }
            // 4-1. PHP: composer.json & composer.lock
            else if (lowerName.equals("composer.json")) {
                parseComposerJson(file, packagesMap);
            } else if (lowerName.equals("composer.lock")) {
                parseComposerLock(file, packagesMap);
            }
            // 5. Rust: Cargo.toml & Cargo.lock
            else if (lowerName.equals("cargo.toml")) {
                parseCargo(file, packagesMap);
            } else if (lowerName.equals("cargo.lock")) {
                parseCargoLock(file, packagesMap);
            }
            // 6. Go: go.mod & go.sum
            else if (lowerName.equals("go.mod")) {
                parseGoMod(file, packagesMap);
            } else if (lowerName.equals("go.sum")) {
                parseGoSum(file, packagesMap);
            }
            // 7. C# / .NET / Unity: *.csproj, Directory.Build.props, packages.config
            else if (lowerName.endsWith(".csproj") || lowerName.endsWith(".fsproj") || lowerName.equals("directory.build.props")) {
                parseCsproj(file, packagesMap);
            } else if (lowerName.equals("packages.config")) {
                parsePackagesConfig(file, packagesMap);
            }
            // 8. Unity Game Engine: manifest.json (Packages/manifest.json)
            else if (lowerName.equals("manifest.json") && file.getParent() != null && file.getParent().endsWith("Packages")) {
                parseUnityManifest(file, packagesMap);
            }
            // 9. C / C++: vcpkg.json, conanfile.txt, CMakeLists.txt
            else if (lowerName.equals("vcpkg.json")) {
                parseVcpkg(file, packagesMap);
            } else if (lowerName.equals("conanfile.txt")) {
                parseConan(file, packagesMap);
            } else if (lowerName.equals("cmakelists.txt")) {
                parseCMake(file, packagesMap);
            }
            // 10. Mobile (iOS / macOS): Podfile, Package.swift
            else if (lowerName.equals("podfile")) {
                parsePodfile(file, packagesMap);
            } else if (lowerName.equals("package.swift")) {
                parseSwiftPackage(file, packagesMap);
            }
            // 11. Mobile (Flutter / Dart): pubspec.yaml
            else if (lowerName.equals("pubspec.yaml")) {
                parsePubspec(file, packagesMap);
            }
        } catch (Exception e) {
            log.debug("[UniversalScanner] 파일 파싱 스킵 ({}): {}", fileName, e.getMessage());
        }
    }

    private void parseGradle(Path file, Map<String, LLMAnalysisService.SbomPackageDetail> map) throws IOException {
        String content = Files.readString(file, StandardCharsets.UTF_8);

        // 1. 플러그인 실제 버전 감지 (예: id 'org.springframework.boot' version '3.4.1')
        String bootVersion = null;
        Matcher pm = GRADLE_PLUGIN_PATTERN.matcher(content);
        while (pm.find()) {
            String plugin = pm.group(1).trim();
            String version = pm.group(2).trim();
            map.putIfAbsent(plugin, new LLMAnalysisService.SbomPackageDetail(plugin, version, false, "Gradle-Plugin"));
            if (plugin.equals("org.springframework.boot") || plugin.contains("spring.boot")) {
                bootVersion = version;
            }
        }

        // 2. 실제 코드에 선언된 직접 의존성만 정확히 파싱 (가짜 하위 의존성 날조 금지)
        Matcher m = GRADLE_DEP_PATTERN.matcher(content);
        while (m.find()) {
            String group = m.group(1).trim();
            String name = m.group(2).trim();
            String version = m.group(3) != null ? m.group(3).trim() : null;

            if (group.startsWith("org.springframework.boot") && bootVersion != null) {
                if (version == null || version.isBlank() || "(managed)".equals(version)) {
                    version = bootVersion;
                }
            } else if (version == null || version.isBlank()) {
                version = "(managed)";
            }

            String fullName = group + ":" + name;
            map.putIfAbsent(fullName, new LLMAnalysisService.SbomPackageDetail(fullName, version, false, "Maven/Gradle"));
        }
    }

    private void parseGradleLockfile(Path file, Map<String, LLMAnalysisService.SbomPackageDetail> map) throws IOException {
        List<String> lines = Files.readAllLines(file, StandardCharsets.UTF_8);
        for (String line : lines) {
            String trimmed = line.trim();
            if (trimmed.startsWith("#") || trimmed.isBlank() || trimmed.startsWith("empty=")) {
                continue;
            }
            int eqIdx = trimmed.indexOf('=');
            String depPart = eqIdx != -1 ? trimmed.substring(0, eqIdx).trim() : trimmed;
            String[] parts = depPart.split(":");
            if (parts.length >= 3) {
                String fullName = parts[0] + ":" + parts[1];
                String version = parts[2];
                map.put(fullName, new LLMAnalysisService.SbomPackageDetail(fullName, version, true, "Gradle-Lockfile"));
            }
        }
    }

    private void parseMaven(Path file, Map<String, LLMAnalysisService.SbomPackageDetail> map) throws IOException {
        String content = Files.readString(file, StandardCharsets.UTF_8);
        Matcher pm = MAVEN_PARENT_PATTERN.matcher(content);
        String parentGroupId = null;
        String parentVersion = null;
        if (pm.find()) {
            parentGroupId = pm.group(1).trim();
            String parentArtifact = pm.group(2).trim();
            parentVersion = pm.group(3).trim();
            String parentFullName = parentGroupId + ":" + parentArtifact;
            map.putIfAbsent(parentFullName, new LLMAnalysisService.SbomPackageDetail(parentFullName, parentVersion, false, "Maven-Parent"));
        }

        Matcher m = MAVEN_DEP_PATTERN.matcher(content);
        while (m.find()) {
            String group = m.group(1).trim();
            String artifact = m.group(2).trim();
            String version = m.group(3) != null ? m.group(3).trim() : ((parentVersion != null && group.equals(parentGroupId)) ? parentVersion : "(managed)");
            String fullName = group + ":" + artifact;
            map.putIfAbsent(fullName, new LLMAnalysisService.SbomPackageDetail(fullName, version, false, "Maven"));
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

    private void parsePackageLockJson(Path file, Map<String, LLMAnalysisService.SbomPackageDetail> map) {
        try {
            JsonNode root = objectMapper.readTree(file.toFile());
            Set<String> directNames = new HashSet<>();

            JsonNode packagesNode = root.path("packages");
            if (packagesNode.isObject()) {
                // npm lockfile v3: packages[""] represents the root project manifest
                JsonNode rootPkg = packagesNode.path("");
                if (rootPkg.isObject()) {
                    for (String depField : List.of("dependencies", "devDependencies")) {
                        JsonNode deps = rootPkg.path(depField);
                        if (deps.isObject()) {
                            deps.fieldNames().forEachRemaining(directNames::add);
                        }
                    }
                }

                packagesNode.fieldNames().forEachRemaining(key -> {
                    if (!key.isBlank()) {
                        String name = key.startsWith("node_modules/") ? key.substring("node_modules/".length()) : key;
                        String ver = packagesNode.path(key).path("version").asText("");
                        if (!name.isBlank() && !ver.isBlank() && !name.contains("node_modules/")) {
                            LLMAnalysisService.SbomPackageDetail existing = map.get(name);
                            boolean isIndirect = (existing != null)
                                    ? existing.indirect()
                                    : !directNames.contains(name);
                            map.put(name, new LLMAnalysisService.SbomPackageDetail(name, ver, isIndirect, "npm-lockfile"));
                        }
                    }
                });
            }
            JsonNode depsNode = root.path("dependencies");
            if (depsNode.isObject()) {
                depsNode.fieldNames().forEachRemaining(name -> {
                    String ver = depsNode.path(name).path("version").asText("");
                    if (!name.isBlank() && !ver.isBlank()) {
                        LLMAnalysisService.SbomPackageDetail existing = map.get(name);
                        boolean isIndirect = (existing != null)
                                ? existing.indirect()
                                : !directNames.contains(name);
                        map.putIfAbsent(name, new LLMAnalysisService.SbomPackageDetail(name, ver, isIndirect, "npm-lockfile"));
                    }
                });
            }
        } catch (Exception e) {
            log.debug("[UniversalScanner] package-lock.json 파싱 스킵: {}", e.getMessage());
        }
    }

    private void parseYarnLock(Path file, Map<String, LLMAnalysisService.SbomPackageDetail> map) {
        try {
            List<String> lines = Files.readAllLines(file, StandardCharsets.UTF_8);
            String currentPkg = null;
            for (String rawLine : lines) {
                String line = rawLine.trim();
                if (line.isEmpty() || line.startsWith("#")) continue;
                if (!rawLine.startsWith(" ") && !rawLine.startsWith("\t") && line.endsWith(":")) {
                    String firstDep = line.split(",")[0].trim().replace("\"", "").replace("'", "").replace(":", "");
                    int atIdx = firstDep.lastIndexOf('@');
                    if (atIdx > 0) {
                        currentPkg = firstDep.substring(0, atIdx);
                    }
                } else if (currentPkg != null && line.startsWith("version ")) {
                    String ver = line.substring("version ".length()).replace("\"", "").replace("'", "").trim();
                    if (!currentPkg.isBlank() && !ver.isBlank()) {
                        LLMAnalysisService.SbomPackageDetail existing = map.get(currentPkg);
                        boolean isIndirect = (existing != null) ? existing.indirect() : true;
                        map.put(currentPkg, new LLMAnalysisService.SbomPackageDetail(currentPkg, ver, isIndirect, "yarn.lock"));
                    }
                    currentPkg = null;
                }
            }
        } catch (Exception e) {
            log.debug("[UniversalScanner] yarn.lock 파싱 스킵: {}", e.getMessage());
        }
    }

    private void parsePnpmLock(Path file, Map<String, LLMAnalysisService.SbomPackageDetail> map) {
        try {
            List<String> lines = Files.readAllLines(file, StandardCharsets.UTF_8);
            boolean inPackages = false;
            for (String rawLine : lines) {
                String line = rawLine.trim();
                if (line.equals("packages:")) {
                    inPackages = true;
                    continue;
                }
                if (inPackages) {
                    if (!rawLine.startsWith(" ") && !rawLine.startsWith("\t") && line.endsWith(":") && !line.equals("packages:")) {
                        inPackages = false;
                        continue;
                    }
                    if (line.startsWith("/") || line.startsWith("'") || line.startsWith("\"")) {
                        String clean = line.replace("'", "").replace("\"", "").replace(":", "").trim();
                        if (clean.startsWith("/")) clean = clean.substring(1);
                        int atIdx = clean.lastIndexOf('@');
                        if (atIdx > 0) {
                            String name = clean.substring(0, atIdx);
                            String ver = clean.substring(atIdx + 1);
                            int parenIdx = ver.indexOf('(');
                            if (parenIdx > 0) ver = ver.substring(0, parenIdx).trim();
                            if (!name.isBlank() && !ver.isBlank()) {
                                LLMAnalysisService.SbomPackageDetail existing = map.get(name);
                                boolean isIndirect = (existing != null) ? existing.indirect() : true;
                                map.put(name, new LLMAnalysisService.SbomPackageDetail(name, ver, isIndirect, "pnpm-lock"));
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            log.debug("[UniversalScanner] pnpm-lock.yaml 파싱 스킵: {}", e.getMessage());
        }
    }

    private void parsePythonReqs(Path file, Map<String, LLMAnalysisService.SbomPackageDetail> map) throws IOException {
        List<String> lines = Files.readAllLines(file, StandardCharsets.UTF_8);
        for (String rawLine : lines) {
            String line = rawLine.trim();
            // 주석 및 빈 줄, pip 옵션(-r, -i, -f, --extra-index-url 등) 제외
            if (line.isEmpty() || line.startsWith("#") || line.startsWith("-")) {
                continue;
            }
            // 인라인 주석 제거: "fastapi>=0.100 # web framework" -> "fastapi>=0.100"
            int commentIdx = line.indexOf('#');
            if (commentIdx != -1) {
                line = line.substring(0, commentIdx).trim();
            }
            // 환경 마커 제거: "pywin32; sys_platform == 'win32'" -> "pywin32"
            int semiIdx = line.indexOf(';');
            if (semiIdx != -1) {
                line = line.substring(0, semiIdx).trim();
            }
            if (line.isEmpty()) continue;

            // 버전 연산자 분리 (==, >=, <=, ~=, !=, <, >, @)
            String name;
            String ver = "latest";
            String[] split = line.split("[><=~@!]+", 2);
            name = split[0].trim();
            if (split.length > 1) {
                ver = split[1].split("[,;\\s]+")[0].trim();
            }

            // extras 제거: "uvicorn[standard]" -> name: "uvicorn"
            int bracketIdx = name.indexOf('[');
            if (bracketIdx != -1) {
                name = name.substring(0, bracketIdx).trim();
            }

            if (!name.isBlank()) {
                map.putIfAbsent(name, new LLMAnalysisService.SbomPackageDetail(name, ver, false, "PyPI(Python)"));
            }
        }
    }

    private boolean isInsideRequirementsDir(Path file) {
        if (file == null || file.getParent() == null) return false;
        Path parent = file.getParent();
        String parentName = parent.getFileName() != null ? parent.getFileName().toString().toLowerCase() : "";
        return parentName.contains("requirements") || parentName.equals("reqs") || parentName.equals("pip");
    }

    private void parsePythonSetup(Path file, Map<String, LLMAnalysisService.SbomPackageDetail> map) {
        try {
            List<String> lines = Files.readAllLines(file, StandardCharsets.UTF_8);
            boolean inInstallRequires = false;
            for (String rawLine : lines) {
                String line = rawLine.trim();
                if (line.isEmpty() || line.startsWith("#")) continue;

                if (line.contains("install_requires")) {
                    inInstallRequires = true;
                    if (line.contains("]") || (line.endsWith(")") && !line.contains("["))) {
                        extractPackagesFromLine(line, map);
                        inInstallRequires = false;
                    }
                    continue;
                }

                if (inInstallRequires) {
                    if (line.equals("]") || line.equals(")") || (line.startsWith("[") && line.endsWith("]"))) {
                        inInstallRequires = false;
                        continue;
                    }
                    extractPackagesFromLine(line, map);
                }
            }
        } catch (Exception e) {
            log.debug("[UniversalScanner] setup.py/cfg 파싱 스킵: {}", e.getMessage());
        }
    }

    private void extractPackagesFromLine(String line, Map<String, LLMAnalysisService.SbomPackageDetail> map) {
        String clean = line.replace("\"", "").replace("'", "").replace(",", "").trim();
        int commentIdx = clean.indexOf('#');
        if (commentIdx != -1) clean = clean.substring(0, commentIdx).trim();
        int semiIdx = clean.indexOf(';');
        if (semiIdx != -1) clean = clean.substring(0, semiIdx).trim();
        if (clean.isEmpty()) return;

        String[] split = clean.split("[><=~@!]+", 2);
        String name = split[0].trim();
        String ver = "latest";
        if (split.length > 1) {
            ver = split[1].split("[,;\\s]+")[0].trim();
        }
        int bracketIdx = name.indexOf('[');
        if (bracketIdx != -1) {
            name = name.substring(0, bracketIdx).trim();
        }
        if (!name.isBlank() && !name.contains("install_requires") && !name.equals("=") && !name.contains("(")) {
            map.putIfAbsent(name, new LLMAnalysisService.SbomPackageDetail(name, ver, false, "PyPI(Python)"));
        }
    }

    private void parsePyprojectToml(Path file, Map<String, LLMAnalysisService.SbomPackageDetail> map) {
        try {
            List<String> lines = Files.readAllLines(file, StandardCharsets.UTF_8);
            boolean inDependencies = false;
            boolean inPoetryDependencies = false;

            for (String rawLine : lines) {
                String line = rawLine.trim();
                if (line.isEmpty() || line.startsWith("#")) continue;

                if (line.startsWith("[") && line.endsWith("]")) {
                    inDependencies = line.equals("[project]") || line.equals("[project.dependencies]") || line.equals("[project.optional-dependencies]");
                    inPoetryDependencies = line.equals("[tool.poetry.dependencies]") || line.equals("[tool.poetry.dev-dependencies]");
                    continue;
                }

                // 1. PEP 621: dependencies = [ ... ]
                if (line.startsWith("dependencies = [") || line.equals("dependencies = [")) {
                    inDependencies = true;
                    continue;
                }

                if (inDependencies) {
                    if (line.equals("]")) {
                        inDependencies = false;
                        continue;
                    }
                    if (line.startsWith("\"") || line.startsWith("'")) {
                        String clean = line.replace("\"", "").replace("'", "").replace(",", "").trim();
                        int commentIdx = clean.indexOf('#');
                        if (commentIdx != -1) clean = clean.substring(0, commentIdx).trim();
                        int semiIdx = clean.indexOf(';');
                        if (semiIdx != -1) clean = clean.substring(0, semiIdx).trim();

                        String[] split = clean.split("[><=~@!]+", 2);
                        String name = split[0].trim();
                        int bIdx = name.indexOf('[');
                        if (bIdx != -1) name = name.substring(0, bIdx).trim();
                        String ver = (split.length > 1) ? split[1].split("[,;\\s]+")[0].trim() : "latest";

                        if (!name.isBlank()) {
                            map.putIfAbsent(name, new LLMAnalysisService.SbomPackageDetail(name, ver, false, "PyPI(Python)"));
                        }
                    }
                }

                // 2. Poetry: name = "^version" or name = { version = "..." }
                if (inPoetryDependencies && line.contains("=")) {
                    int eqIdx = line.indexOf('=');
                    String name = line.substring(0, eqIdx).trim();
                    if (!name.equals("python")) {
                        String verPart = line.substring(eqIdx + 1).replace("\"", "").replace("'", "").trim();
                        int bIdx = name.indexOf('[');
                        if (bIdx != -1) name = name.substring(0, bIdx).trim();
                        String ver = verPart.startsWith("^") ? verPart.substring(1) : verPart;
                        if (ver.contains("version")) {
                            int vIdx = ver.indexOf("version");
                            ver = ver.substring(vIdx).replaceAll("[^0-9a-zA-Z.]", "");
                        }
                        if (!name.isBlank() && !ver.isBlank()) {
                            map.putIfAbsent(name, new LLMAnalysisService.SbomPackageDetail(name, ver, false, "PyPI(Python)"));
                        }
                    }
                }
            }
        } catch (Exception e) {
            log.debug("[UniversalScanner] pyproject.toml 파싱 스킵: {}", e.getMessage());
        }
    }

    private void parsePipfile(Path file, Map<String, LLMAnalysisService.SbomPackageDetail> map) {
        try {
            List<String> lines = Files.readAllLines(file, StandardCharsets.UTF_8);
            boolean inPackages = false;
            for (String rawLine : lines) {
                String line = rawLine.trim();
                if (line.isEmpty() || line.startsWith("#")) continue;

                if (line.startsWith("[") && line.endsWith("]")) {
                    inPackages = line.equalsIgnoreCase("[packages]") || line.equalsIgnoreCase("[dev-packages]");
                    continue;
                }

                if (inPackages && line.contains("=")) {
                    int eqIdx = line.indexOf('=');
                    String name = line.substring(0, eqIdx).trim();
                    String ver = line.substring(eqIdx + 1).replace("\"", "").replace("'", "").trim();
                    if (ver.equals("*")) ver = "latest";
                    if (!name.isBlank()) {
                        map.putIfAbsent(name, new LLMAnalysisService.SbomPackageDetail(name, ver, false, "PyPI(Python)"));
                    }
                }
            }
        } catch (Exception e) {
            log.debug("[UniversalScanner] Pipfile 파싱 스킵: {}", e.getMessage());
        }
    }

    private void parsePoetryLock(Path file, Map<String, LLMAnalysisService.SbomPackageDetail> map) {
        try {
            List<String> lines = Files.readAllLines(file, StandardCharsets.UTF_8);
            String currentName = null;
            for (String line : lines) {
                String trimmed = line.trim();
                if (trimmed.equals("[[package]]")) {
                    currentName = null;
                } else if (trimmed.startsWith("name = \"")) {
                    currentName = trimmed.substring(8, trimmed.length() - 1);
                } else if (trimmed.startsWith("version = \"") && currentName != null) {
                    String ver = trimmed.substring(11, trimmed.length() - 1);
                    if (!currentName.isBlank() && !ver.isBlank()) {
                        LLMAnalysisService.SbomPackageDetail existing = map.get(currentName);
                        boolean isIndirect = (existing != null) ? existing.indirect() : true;
                        map.put(currentName, new LLMAnalysisService.SbomPackageDetail(currentName, ver, isIndirect, "poetry.lock"));
                    }
                    currentName = null;
                }
            }
        } catch (Exception e) {
            log.debug("[UniversalScanner] poetry.lock 파싱 스킵: {}", e.getMessage());
        }
    }

    private void parsePipfileLock(Path file, Map<String, LLMAnalysisService.SbomPackageDetail> map) {
        try {
            JsonNode root = objectMapper.readTree(file.toFile());
            for (String section : List.of("default", "develop")) {
                JsonNode secNode = root.path(section);
                if (secNode.isObject()) {
                    secNode.fieldNames().forEachRemaining(pkgName -> {
                        String ver = secNode.path(pkgName).path("version").asText("").replace("==", "").trim();
                        if (!pkgName.isBlank() && !ver.isBlank()) {
                            LLMAnalysisService.SbomPackageDetail existing = map.get(pkgName);
                            boolean isIndirect = (existing != null) ? existing.indirect() : true;
                            map.put(pkgName, new LLMAnalysisService.SbomPackageDetail(pkgName, ver, isIndirect, "Pipfile.lock"));
                        }
                    });
                }
            }
        } catch (Exception e) {
            log.debug("[UniversalScanner] Pipfile.lock 파싱 스킵: {}", e.getMessage());
        }
    }

    private void parseComposerJson(Path file, Map<String, LLMAnalysisService.SbomPackageDetail> map) {
        try {
            JsonNode root = objectMapper.readTree(file.toFile());
            for (String section : List.of("require", "require-dev")) {
                JsonNode secNode = root.path(section);
                if (secNode.isObject()) {
                    secNode.fieldNames().forEachRemaining(pkgName -> {
                        if (!pkgName.equals("php")) {
                            String ver = secNode.path(pkgName).asText("latest");
                            map.putIfAbsent(pkgName, new LLMAnalysisService.SbomPackageDetail(pkgName, ver, false, "Composer(PHP)"));
                        }
                    });
                }
            }
        } catch (Exception e) {
            log.debug("[UniversalScanner] composer.json 파싱 스킵: {}", e.getMessage());
        }
    }

    private void parseComposerLock(Path file, Map<String, LLMAnalysisService.SbomPackageDetail> map) {
        try {
            JsonNode root = objectMapper.readTree(file.toFile());
            for (String section : List.of("packages", "packages-dev")) {
                JsonNode arr = root.path(section);
                if (arr.isArray()) {
                    for (JsonNode item : arr) {
                        String name = item.path("name").asText("");
                        String ver = item.path("version").asText("");
                        if (ver.startsWith("v")) ver = ver.substring(1);
                        if (!name.isBlank() && !ver.isBlank()) {
                            LLMAnalysisService.SbomPackageDetail existing = map.get(name);
                            boolean isIndirect = (existing != null) ? existing.indirect() : true;
                            map.put(name, new LLMAnalysisService.SbomPackageDetail(name, ver, isIndirect, "composer.lock"));
                        }
                    }
                }
            }
        } catch (Exception e) {
            log.debug("[UniversalScanner] composer.lock 파싱 스킵: {}", e.getMessage());
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

    private void parseCargoLock(Path file, Map<String, LLMAnalysisService.SbomPackageDetail> map) {
        try {
            List<String> lines = Files.readAllLines(file, StandardCharsets.UTF_8);
            String currentName = null;
            for (String line : lines) {
                String trimmed = line.trim();
                if (trimmed.startsWith("name = \"")) {
                    currentName = trimmed.substring(8, trimmed.length() - 1);
                } else if (trimmed.startsWith("version = \"") && currentName != null) {
                    String ver = trimmed.substring(11, trimmed.length() - 1);
                    LLMAnalysisService.SbomPackageDetail existing = map.get(currentName);
                    boolean isIndirect = (existing != null) ? existing.indirect() : true;
                    map.put(currentName, new LLMAnalysisService.SbomPackageDetail(currentName, ver, isIndirect, "Cargo.lock"));
                    currentName = null;
                }
            }
        } catch (Exception e) {
            log.debug("[UniversalScanner] Cargo.lock 파싱 스킵: {}", e.getMessage());
        }
    }

    private void parseGoMod(Path file, Map<String, LLMAnalysisService.SbomPackageDetail> map) throws IOException {
        List<String> lines = Files.readAllLines(file, StandardCharsets.UTF_8);
        boolean inRequire = false;
        for (String rawLine : lines) {
            String line = rawLine.trim();
            if (line.startsWith("require (")) {
                inRequire = true;
                continue;
            }
            if (inRequire && line.equals(")")) {
                inRequire = false;
                continue;
            }
            String targetLine = line;
            if (line.startsWith("require ") && !line.startsWith("require (")) {
                targetLine = line.substring("require ".length()).trim();
            } else if (!inRequire) {
                continue;
            }

            Matcher m = GO_MOD_PATTERN.matcher(targetLine);
            if (m.find()) {
                String name = m.group(1).trim();
                String ver = m.group(2).trim();
                boolean isIndirect = targetLine.contains("// indirect");
                LLMAnalysisService.SbomPackageDetail existing = map.get(name);
                if (existing == null || (existing.indirect() && !isIndirect)) {
                    map.put(name, new LLMAnalysisService.SbomPackageDetail(name, ver, isIndirect, "Go-Modules"));
                }
            }
        }
    }

    private void parseGoSum(Path file, Map<String, LLMAnalysisService.SbomPackageDetail> map) {
        try {
            List<String> lines = Files.readAllLines(file, StandardCharsets.UTF_8);
            for (String line : lines) {
                String trimmed = line.trim();
                if (trimmed.isBlank() || trimmed.contains("/go.mod ")) {
                    continue;
                }
                String[] parts = trimmed.split("\\s+");
                if (parts.length >= 2) {
                    String mod = parts[0].trim();
                    String ver = parts[1].trim();
                    if (ver.startsWith("v")) ver = ver.substring(1);
                    map.putIfAbsent(mod, new LLMAnalysisService.SbomPackageDetail(mod, ver, true, "go.sum"));
                }
            }
        } catch (Exception e) {
            log.debug("[UniversalScanner] go.sum 파싱 스킵: {}", e.getMessage());
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
            String version = m.group(2).trim();
            map.putIfAbsent(id, new LLMAnalysisService.SbomPackageDetail(id, version, false, "NuGet"));
        }
    }

    private void parseUnityManifest(Path file, Map<String, LLMAnalysisService.SbomPackageDetail> map) throws IOException {
        JsonNode root = objectMapper.readTree(file.toFile());
        JsonNode deps = root.path("dependencies");
        if (deps.isObject()) {
            deps.fieldNames().forEachRemaining(name -> {
                String ver = deps.path(name).asText("latest");
                map.putIfAbsent(name, new LLMAnalysisService.SbomPackageDetail(name, ver, false, "Unity-Package"));
            });
        }
    }

    private void parseVcpkg(Path file, Map<String, LLMAnalysisService.SbomPackageDetail> map) throws IOException {
        JsonNode root = objectMapper.readTree(file.toFile());
        JsonNode deps = root.path("dependencies");
        if (deps.isArray()) {
            for (JsonNode item : deps) {
                if (item.isTextual()) {
                    map.putIfAbsent(item.asText(), new LLMAnalysisService.SbomPackageDetail(item.asText(), "latest", false, "vcpkg(C++)"));
                } else if (item.isObject()) {
                    String name = item.path("name").asText();
                    String ver = item.path("version>=").asText(item.path("version").asText("latest"));
                    if (!name.isBlank()) {
                        map.putIfAbsent(name, new LLMAnalysisService.SbomPackageDetail(name, ver, false, "vcpkg(C++)"));
                    }
                }
            }
        }
    }

    private void parseConan(Path file, Map<String, LLMAnalysisService.SbomPackageDetail> map) throws IOException {
        String content = Files.readString(file, StandardCharsets.UTF_8);
        Matcher m = CONAN_REQ_PATTERN.matcher(content);
        while (m.find()) {
            String name = m.group(1).trim();
            String ver = m.group(2).trim();
            map.putIfAbsent(name, new LLMAnalysisService.SbomPackageDetail(name, ver, false, "Conan(C++)"));
        }
    }

    private void parseCMake(Path file, Map<String, LLMAnalysisService.SbomPackageDetail> map) throws IOException {
        String content = Files.readString(file, StandardCharsets.UTF_8);
        Matcher m = CMAKE_FIND_PACKAGE_PATTERN.matcher(content);
        while (m.find()) {
            String name = m.group(1).trim();
            String ver = m.group(2) != null ? m.group(2).trim() : "system";
            map.putIfAbsent(name, new LLMAnalysisService.SbomPackageDetail(name, ver, false, "CMake(C++)"));
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

    // =========================================================================
    // 실제 Wrapper CLI 프로세스 실행 (저장소에 gradlew/mvnw가 존재하고 설정 활성화 시에만 실행)
    // =========================================================================

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
            command.add("/bin/sh");
            command.add(wrapper.toAbsolutePath().toString());
        }
        command.add("-q");
        command.add("dependencies");
        command.add("--configuration");
        command.add("runtimeClasspath");
        command.add("--no-daemon");
        command.add("--console=plain");
        command.add("-Dorg.gradle.daemon=false");
        command.add("-Dorg.gradle.parallel=false");
        command.add("-Dorg.gradle.welcome=never");
        command.add("-Dorg.gradle.jvmargs=-Xmx128m -XX:MaxMetaspaceSize=64m");

        String output = runProcessWithTimeout(command, rootDir, 90, TimeUnit.SECONDS, "Gradle Wrapper");
        if (output == null || !output.contains("---")) {
            List<String> fallbackCmd = new ArrayList<>(command);
            int idx = fallbackCmd.indexOf("runtimeClasspath");
            if (idx >= 0) {
                fallbackCmd.set(idx, "compileClasspath");
            }
            output = runProcessWithTimeout(fallbackCmd, rootDir, 60, TimeUnit.SECONDS, "Gradle Wrapper (compileClasspath)");
        }

        if (output == null || !output.contains("---")) {
            // 3차 폴백: 특정 configuration 지정 없이 전체 의존성 트리 출력
            List<String> allConfigCmd = new ArrayList<>(command);
            int cfgIdx = allConfigCmd.indexOf("--configuration");
            if (cfgIdx >= 0) {
                allConfigCmd.remove(cfgIdx + 1);
                allConfigCmd.remove(cfgIdx);
            }
            output = runProcessWithTimeout(allConfigCmd, rootDir, 60, TimeUnit.SECONDS, "Gradle Wrapper (all configurations)");
        }

        if (output != null && output.contains("---")) {
            int beforeCount = packagesMap.size();
            parseGradleDependencyTreeOutput(output, packagesMap);
            log.info("[UniversalScanner] 실제 Gradle Wrapper 의존성 트리 해석 완료 (신규/최신화: {}개 추가 반영)",
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

            if (dep.endsWith("(c)")) {
                continue;
            }

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

            version = version.split("\\s+")[0].trim();

            LLMAnalysisService.SbomPackageDetail existing = map.get(name);
            if (existing != null && !existing.indirect()) {
                if (("(managed)".equals(existing.version()) || "BOM-managed".equals(existing.version()) || existing.version().isBlank()) && !"(managed)".equals(version)) {
                    map.put(name, new LLMAnalysisService.SbomPackageDetail(name, version, false, "Maven/Gradle"));
                }
            } else {
                map.put(name, new LLMAnalysisService.SbomPackageDetail(name, version, isIndirect, "Maven/Gradle"));
            }
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
            command.add("/bin/sh");
            command.add(wrapper.toAbsolutePath().toString());
        }
        command.add("-q");
        command.add("dependency:tree");
        command.add("-DoutputType=text");

        String output = runProcessWithTimeout(command, rootDir, 60, TimeUnit.SECONDS, "Maven Wrapper");
        if (output != null && (output.contains("+-") || output.contains("\\-"))) {
            int beforeCount = packagesMap.size();
            parseMavenDependencyTreeOutput(output, packagesMap);
            log.info("[UniversalScanner] 실제 Maven Wrapper 의존성 트리 해석 완료 (신규/최신화: {}개 추가 반영)",
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

    private String runProcessWithTimeout(List<String> command, Path rootDir, long timeout, TimeUnit unit, String processName) {
        ProcessBuilder pb = new ProcessBuilder(command);
        pb.directory(rootDir.toFile());
        pb.redirectErrorStream(true);
        // Render 512MB RAM 컨테이너 환경에서 Fork된 JVM 프로세스가 cgroup OOM Kill(코드 137)되지 않도록 엄격한 힙/메타스페이스 상한 지정
        pb.environment().put("GRADLE_OPTS", "-Xmx128m -XX:MaxMetaspaceSize=64m -Dorg.gradle.daemon=false -Dorg.gradle.parallel=false");
        pb.environment().put("JAVA_TOOL_OPTIONS", "-Xmx128m -XX:MaxMetaspaceSize=64m");
        pb.environment().put("MAVEN_OPTS", "-Xmx128m -XX:MaxMetaspaceSize=64m");
        String userHome = System.getProperty("user.home");
        String gradleUserHome = (userHome != null && !userHome.isBlank()) ? (userHome + "/.gradle") : "/home/appuser/.gradle";
        pb.environment().put("GRADLE_USER_HOME", gradleUserHome);

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
                process.descendants().forEach(ProcessHandle::destroyForcibly);
                process.destroyForcibly();
                readFuture.cancel(true);
                log.warn("[UniversalScanner] {} 프로세스 타임아웃 초과 ({} {})", processName, timeout, unit.name().toLowerCase());
                return null;
            }

            if (process.exitValue() != 0) {
                String errOutput = readFuture.get(2, TimeUnit.SECONDS);
                String preview = (errOutput != null && errOutput.length() > 400)
                        ? errOutput.substring(errOutput.length() - 400)
                        : (errOutput != null ? errOutput : "");
                log.warn("[UniversalScanner] {} 프로세스 비정상 종료 (Exit code: {}): {}",
                        processName, process.exitValue(), preview);
                return null;
            }

            return readFuture.get(5, TimeUnit.SECONDS);
        } catch (Exception e) {
            log.warn("[UniversalScanner] {} 실행 중 오류 발생: {}", processName, e.getMessage());
            return null;
        }
    }
}
