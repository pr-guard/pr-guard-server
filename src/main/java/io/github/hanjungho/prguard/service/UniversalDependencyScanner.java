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
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * 프로젝트 내 모든 프로그래밍 언어, 모바일, 게임 엔진 및 프레임워크의 의존성 매니페스트를 직접 탐색하고 파싱하는 범용 SBOM 추출기.
 * (Lock 파일이 없더라도 build.gradle, .csproj, CMakeLists.txt, vcpkg, Conan, Podfile, pubspec, Unity manifest 등 지원)
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class UniversalDependencyScanner {

    private final ObjectMapper objectMapper;

    @org.springframework.beans.factory.annotation.Value("${registry.pypi.url:https://pypi.org/pypi}")
    private String pypiRegistryUrl = "https://pypi.org/pypi";

    @org.springframework.beans.factory.annotation.Value("${registry.npm.url:https://registry.npmjs.org}")
    private String npmRegistryUrl = "https://registry.npmjs.org";

    @org.springframework.beans.factory.annotation.Value("${registry.cargo.url:https://crates.io/api/v1/crates}")
    private String cargoRegistryUrl = "https://crates.io/api/v1/crates";

    @org.springframework.beans.factory.annotation.Value("${registry.go.url:https://proxy.golang.org}")
    private String goProxyUrl = "https://proxy.golang.org";

    @org.springframework.beans.factory.annotation.Value("${registry.nuget.url:https://azuresearch-usnc.nuget.org/query}")
    private String nugetRegistryUrl = "https://azuresearch-usnc.nuget.org/query";

    @org.springframework.beans.factory.annotation.Value("${scanner.wrapper.enabled:false}")
    private boolean wrapperExecutionEnabled = false;

    private String cleanRegistryUrl(String url, String fallback) {
        if (url == null || url.isBlank()) return fallback;
        return url.replaceAll("/+$", "");
    }

    private static final Set<String> IGNORED_DIRS = Set.of(
            ".git", ".gradle", ".idea", "node_modules", "target", "build", "bin", "obj",
            ".vs", ".vscode", "vendor", "dist", "out", ".next", ".nuxt",
            "venv", ".venv", "env", ".env", "__pycache__", ".pytest_cache", ".mypy_cache",
            ".tox", "Pods", "packages"
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

    // =========================================================================
    // [Manifest-less 엔진] 소스코드 정밀 타격 의존성 추론 패턴 및 표준 라이브러리 카탈로그
    // =========================================================================
    // 1. Python 소스코드 패턴 & 표준 라이브러리
    private static final Pattern PY_IMPORT_PATTERN = Pattern.compile("^\\s*import\\s+([a-zA-Z0-9_]+)");
    private static final Pattern PY_FROM_PATTERN = Pattern.compile("^\\s*from\\s+([a-zA-Z0-9_]+)\\s+import");
    private static final Set<String> PYTHON_STDLIB = Set.of(
            "abc", "argparse", "array", "ast", "asynchat", "asyncio", "asyncore", "atexit",
            "audioop", "base64", "bdb", "binascii", "binhex", "bisect", "builtins", "bz2",
            "cprofile", "calendar", "cgi", "cgitb", "chunk", "cmath", "cmd", "code", "codecs",
            "codeop", "collections", "colorsys", "compileall", "concurrent", "configparser",
            "contextlib", "contextvars", "copy", "copyreg", "crypt", "csv", "ctypes", "curses",
            "dataclasses", "datetime", "dbm", "decimal", "difflib", "dis", "distutils", "doctest",
            "email", "encodings", "ensurepip", "enum", "errno", "faulthandler", "fcntl", "filecmp",
            "fileinput", "fnmatch", "formatter", "fractions", "ftplib", "functools", "gc", "getopt",
            "getpass", "gettext", "glob", "graphlib", "grp", "gzip", "hashlib", "heapq", "hmac",
            "html", "http", "imaplib", "imghdr", "imp", "importlib", "inspect", "io", "ipaddress",
            "itertools", "json", "keyword", "lib2to3", "linecache", "locale", "logging", "lzma",
            "mailbox", "mailcap", "marshal", "math", "mimetypes", "mmap", "modulefinder", "msilib",
            "msvcrt", "multiprocessing", "netrc", "nis", "nntplib", "numbers", "operator", "optparse",
            "os", "ossaudiodev", "parser", "pathlib", "pdb", "pickle", "pickletools", "pipes",
            "pkgutil", "platform", "plistlib", "poplib", "posix", "posixpath", "pprint", "profile",
            "pstats", "pty", "pwd", "py_compile", "pyclbr", "pydoc", "queue", "quopri", "random",
            "re", "readline", "reprlib", "resource", "rlcompleter", "runpy", "sched", "secrets",
            "select", "selectors", "shelve", "shlex", "shutil", "signal", "site", "smtpd", "smtplib",
            "sndhdr", "socket", "socketserver", "spwd", "sqlite3", "ssl", "stat", "statistics",
            "string", "stringprep", "struct", "subprocess", "sunau", "symbol", "symtable", "sys",
            "sysconfig", "syslog", "tabnanny", "tarfile", "telnetlib", "tempfile", "termios",
            "test", "textwrap", "threading", "time", "timeit", "tkinter", "token", "tokenize",
            "tomllib", "trace", "traceback", "tracemalloc", "tty", "turtle", "turtledemo", "types",
            "typing", "unicodedata", "unittest", "urllib", "uu", "uuid", "venv", "warnings",
            "wave", "weakref", "webbrowser", "winreg", "winsound", "wsgiref", "xdrlib", "xml",
            "xmlrpc", "zipapp", "zipfile", "zipimport", "zlib", "zoneinfo"
    );
    private static final Map<String, String> PYTHON_MODULE_TO_PKG = Map.ofEntries(
            Map.entry("cv2", "opencv-python"),
            Map.entry("PIL", "Pillow"),
            Map.entry("sklearn", "scikit-learn"),
            Map.entry("bs4", "beautifulsoup4"),
            Map.entry("yaml", "PyYAML"),
            Map.entry("dotenv", "python-dotenv"),
            Map.entry("dateutil", "python-dateutil"),
            Map.entry("jwt", "PyJWT"),
            Map.entry("Crypto", "pycryptodome"),
            Map.entry("crypto", "pycryptodome"),
            Map.entry("psycopg2", "psycopg2-binary"),
            Map.entry("jose", "python-jose"),
            Map.entry("multipart", "python-multipart"),
            Map.entry("magic", "python-magic"),
            Map.entry("git", "GitPython"),
            Map.entry("serial", "pyserial")
    );

    // 2. Node.js 소스코드 패턴 & 내장 모듈
    private static final Pattern NODE_REQUIRE_PATTERN = Pattern.compile("require\\s*\\(\\s*['\"]([^'\"\\r\\n]+)['\"]\\s*\\)");
    private static final Pattern NODE_IMPORT_PATTERN = Pattern.compile("(?:import|export)\\s+.*?from\\s+['\"]([^'\"\\r\\n]+)['\"]");
    private static final Pattern NODE_BARE_IMPORT_PATTERN = Pattern.compile("import\\s+['\"]([^'\"\\r\\n]+)['\"]");
    private static final Set<String> NODE_BUILTINS = Set.of(
            "assert", "async_hooks", "buffer", "child_process", "cluster", "console", "constants",
            "crypto", "dgram", "diagnostics_channel", "dns", "domain", "events", "fs", "fs/promises",
            "http", "http2", "https", "inspector", "module", "net", "os", "path", "path/posix",
            "path/win32", "perf_hooks", "process", "punycode", "querystring", "readline", "repl",
            "stream", "stream/promises", "stream/web", "string_decoder", "sys", "timers",
            "timers/promises", "tls", "trace_events", "tty", "url", "util", "util/types", "v8",
            "vm", "wasi", "worker_threads", "zlib"
    );

    // 3. C# / .NET / Unity
    private static final Pattern CS_USING_PATTERN = Pattern.compile("^\\s*using\\s+(?:static\\s+)?([a-zA-Z0-9_.]+)\\s*;");
    private static final Set<String> CS_SYSTEM_NAMESPACES = Set.of(
            "System", "Microsoft", "Windows", "UnityEditor", "UnityEngine"
    );
    private static final Map<String, String> CS_NAMESPACE_TO_NUGET = Map.ofEntries(
            Map.entry("Newtonsoft.Json", "Newtonsoft.Json"),
            Map.entry("RestSharp", "RestSharp"),
            Map.entry("Dapper", "Dapper"),
            Map.entry("Serilog", "Serilog"),
            Map.entry("NLog", "NLog"),
            Map.entry("AutoMapper", "AutoMapper"),
            Map.entry("NUnit", "NUnit"),
            Map.entry("Moq", "Moq"),
            Map.entry("FluentValidation", "FluentValidation"),
            Map.entry("Polly", "Polly"),
            Map.entry("MediatR", "MediatR"),
            Map.entry("Swashbuckle", "Swashbuckle.AspNetCore"),
            Map.entry("StackExchange.Redis", "StackExchange.Redis"),
            Map.entry("CsvHelper", "CsvHelper"),
            Map.entry("YamlDotNet", "YamlDotNet"),
            Map.entry("Autofac", "Autofac"),
            Map.entry("RabbitMQ.Client", "RabbitMQ.Client"),
            Map.entry("Grpc.Core", "Grpc.Core"),
            Map.entry("Quartz", "Quartz")
    );

    // 4. Go 소스코드 패턴
    private static final Pattern GO_IMPORT_LINE_PATTERN = Pattern.compile("^\\s*(?:[a-zA-Z0-9_]+\\s+)?[\"']([^\"']+)[\"']");

    // 5. Rust 소스코드 패턴
    private static final Pattern RUST_USE_PATTERN = Pattern.compile("^\\s*(?:pub\\s+)?use\\s+([a-zA-Z0-9_]+)::");
    private static final Pattern RUST_EXTERN_PATTERN = Pattern.compile("^\\s*extern\\s+crate\\s+([a-zA-Z0-9_]+)\\s*;");

    // 6. C / C++ 소스코드 패턴 & 주요 라이브러리 매핑
    private static final Pattern CPP_INCLUDE_PATTERN = Pattern.compile("^\\s*#include\\s+<([a-zA-Z0-9_/\\-\\.]+(?:\\.h|\\.hpp)?)>");
    private static final Map<String, String> CPP_HEADER_TO_PKG = Map.ofEntries(
            Map.entry("boost", "boost"),
            Map.entry("fmt", "fmt"),
            Map.entry("spdlog", "spdlog"),
            Map.entry("nlohmann", "nlohmann-json"),
            Map.entry("opencv2", "opencv"),
            Map.entry("openssl", "openssl"),
            Map.entry("curl", "curl"),
            Map.entry("gtest", "gtest"),
            Map.entry("gmock", "gmock"),
            Map.entry("zlib.h", "zlib"),
            Map.entry("sqlite3.h", "sqlite3"),
            Map.entry("yaml-cpp", "yaml-cpp"),
            Map.entry("eigen3", "eigen3"),
            Map.entry("Eigen", "eigen3"),
            Map.entry("google/protobuf", "protobuf")
    );

    // 7. Java / Kotlin 소스코드 패턴 & 외부 라이브러리 매핑
    private static final Pattern JAVA_IMPORT_PATTERN = Pattern.compile("^\\s*import\\s+([a-zA-Z0-9_.]+);?");
    private static final Map<String, String> JAVA_PREFIX_TO_PKG = Map.ofEntries(
            Map.entry("org.springframework.boot", "org.springframework.boot:spring-boot-starter"),
            Map.entry("org.springframework.web", "org.springframework.boot:spring-boot-starter-web"),
            Map.entry("com.fasterxml.jackson", "com.fasterxml.jackson.core:jackson-databind"),
            Map.entry("com.google.gson", "com.google.code.gson:gson"),
            Map.entry("io.jsonwebtoken", "io.jsonwebtoken:jjwt-api"),
            Map.entry("okhttp3", "com.squareup.okhttp3:okhttp"),
            Map.entry("retrofit2", "com.squareup.retrofit2:retrofit"),
            Map.entry("org.apache.commons.lang3", "org.apache.commons:commons-lang3"),
            Map.entry("org.apache.commons.io", "commons-io:commons-io"),
            Map.entry("org.slf4j", "org.slf4j:slf4j-api"),
            Map.entry("ch.qos.logback", "ch.qos.logback:logback-classic"),
            Map.entry("org.bouncycastle", "org.bouncycastle:bcpkix-jdk18on"),
            Map.entry("org.junit.jupiter", "org.junit.jupiter:junit-jupiter")
    );

    // Public Registry API 캐시 (동일 패키지 중복 네트워크 호출 0건 방어)
    private static final Map<String, String> REGISTRY_VERSION_CACHE = new ConcurrentHashMap<>();

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

        // 매니페스트 존재 여부 플래그
        boolean[] hasGradle = new boolean[1];
        boolean[] hasMaven = new boolean[1];
        boolean[] hasPythonManifest = new boolean[1];
        boolean[] hasNodeManifest = new boolean[1];
        boolean[] hasGoManifest = new boolean[1];
        boolean[] hasRustManifest = new boolean[1];
        boolean[] hasDotNetManifest = new boolean[1];
        boolean[] hasCppManifest = new boolean[1];

        // 매니페스트 부재(Manifest-less) 시 소스코드 정밀 타격을 위한 언어별 파일 수집 (OOM 방지: 언어별 최대 50개)
        List<Path> pythonFiles = new ArrayList<>();
        List<Path> nodeFiles = new ArrayList<>();
        List<Path> goFiles = new ArrayList<>();
        List<Path> rustFiles = new ArrayList<>();
        List<Path> dotNetFiles = new ArrayList<>();
        List<Path> cppFiles = new ArrayList<>();
        List<Path> javaFiles = new ArrayList<>();

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
                    String fileName = file.getFileName().toString();
                    String lower = fileName.toLowerCase();

                    // 1. 매니페스트 감지
                    if (lower.equals("build.gradle") || lower.equals("build.gradle.kts")) {
                        hasGradle[0] = true;
                    } else if (lower.equals("pom.xml")) {
                        hasMaven[0] = true;
                    } else if (lower.equals("requirements.txt") || lower.endsWith("-requirements.txt") || lower.equals("pyproject.toml") || lower.equals("setup.py")) {
                        hasPythonManifest[0] = true;
                    } else if (lower.equals("package.json") && !file.toString().contains("node_modules")) {
                        hasNodeManifest[0] = true;
                    } else if (lower.equals("go.mod")) {
                        hasGoManifest[0] = true;
                    } else if (lower.equals("cargo.toml")) {
                        hasRustManifest[0] = true;
                    } else if (lower.endsWith(".csproj") || lower.endsWith(".fsproj") || lower.equals("packages.config") || lower.equals("directory.build.props")) {
                        hasDotNetManifest[0] = true;
                    } else if (lower.equals("cmakelists.txt") || lower.equals("vcpkg.json") || lower.equals("conanfile.txt")) {
                        hasCppManifest[0] = true;
                    }

                    // 2. 소스코드 파일 수집 (I/O 및 메모리 보호: 언어별 최대 50개 샘플링)
                    if (lower.endsWith(".py") && pythonFiles.size() < 50) {
                        pythonFiles.add(file);
                    } else if ((lower.endsWith(".js") || lower.endsWith(".ts") || lower.endsWith(".jsx") || lower.endsWith(".tsx") || lower.endsWith(".mjs") || lower.endsWith(".cjs")) && nodeFiles.size() < 50) {
                        nodeFiles.add(file);
                    } else if (lower.endsWith(".go") && goFiles.size() < 50) {
                        goFiles.add(file);
                    } else if (lower.endsWith(".rs") && rustFiles.size() < 50) {
                        rustFiles.add(file);
                    } else if (lower.endsWith(".cs") && dotNetFiles.size() < 50) {
                        dotNetFiles.add(file);
                    } else if ((lower.endsWith(".cpp") || lower.endsWith(".cc") || lower.endsWith(".cxx") || lower.endsWith(".c") || lower.endsWith(".hpp") || lower.endsWith(".h")) && cppFiles.size() < 50) {
                        cppFiles.add(file);
                    } else if ((lower.endsWith(".java") || lower.endsWith(".kt")) && javaFiles.size() < 50) {
                        javaFiles.add(file);
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

        // 3. [Manifest-less 엔진] 명세서가 아예 없는 프로젝트 소스코드 정밀 타격 의존성 추론 & 매니페스트 자동 합성
        if (!hasPythonManifest[0] && !pythonFiles.isEmpty()) {
            inferAndSynthesizePython(rootDir, pythonFiles, packagesMap);
        }
        if (!hasNodeManifest[0] && !nodeFiles.isEmpty()) {
            inferAndSynthesizeNode(rootDir, nodeFiles, packagesMap);
        }
        if (!hasGoManifest[0] && !goFiles.isEmpty()) {
            inferAndSynthesizeGo(rootDir, goFiles, packagesMap);
        }
        if (!hasRustManifest[0] && !rustFiles.isEmpty()) {
            inferAndSynthesizeRust(rootDir, rustFiles, packagesMap);
        }
        if (!hasDotNetManifest[0] && !dotNetFiles.isEmpty()) {
            inferAndSynthesizeDotNet(rootDir, dotNetFiles, packagesMap);
        }
        if (!hasCppManifest[0] && !cppFiles.isEmpty()) {
            inferAndSynthesizeCpp(rootDir, cppFiles, packagesMap);
        }
        if (!hasGradle[0] && !hasMaven[0] && !javaFiles.isEmpty()) {
            inferAndSynthesizeJava(rootDir, javaFiles, packagesMap);
        }

        List<LLMAnalysisService.SbomPackageDetail> result = new ArrayList<>(packagesMap.values());
        int direct = 0;
        int indirect = 0;
        for (LLMAnalysisService.SbomPackageDetail p : result) {
            if (p.indirect()) indirect++;
            else direct++;
        }
        log.info("[UniversalScanner] 범용 매니페스트 및 간접/추론 의존성 스캔 완료: 직접 {}개, 간접 {}개, 총 {}개 패키지 검출",
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
        Matcher pm = MAVEN_PARENT_PATTERN.matcher(content);
        if (pm.find()) {
            String parentGroup = pm.group(1).trim();
            String parentArtifact = pm.group(2).trim();
            String parentVersion = pm.group(3).trim();
            String parentFullName = parentGroup + ":" + parentArtifact;
            map.putIfAbsent(parentFullName, new LLMAnalysisService.SbomPackageDetail(parentFullName, parentVersion, false, "Maven-Parent"));
        }
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
        if (!wrapperExecutionEnabled) {
            log.info("[UniversalScanner] ⚡ 저지연/경량 스캔 모드: Wrapper 프로세스 다운로드를 건너뛰고 정적 분석 및 Lockfile 자동 합성 엔진으로 즉시 복원합니다.");
            return false;
        }

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

    /**
     * Spring Boot 버전에 호환되는 핵심 하위 서브시스템(Spring Framework, Tomcat 등)의 정규 버전을 산출합니다.
     * 버전 체계가 다른 패키지에 Spring Boot 버전을 그대로 부여하여 발생하는 취약점 오탐(CVE False Positive)을 원천 방지합니다.
     */
    public static String resolveCompatibleVersion(String group, String artifact, String bootVersion) {
        if (group.startsWith("org.springframework.boot")) {
            return bootVersion;
        }
        if (group.startsWith("org.springframework")) {
            if (bootVersion.startsWith("4.")) return "7.0.0";
            if (bootVersion.startsWith("3.4")) return "6.2.1";
            if (bootVersion.startsWith("3.3")) return "6.1.10";
            if (bootVersion.startsWith("3.2")) return "6.1.2";
            if (bootVersion.startsWith("3.1")) return "6.0.9";
            if (bootVersion.startsWith("3.0")) return "6.0.2";
            if (bootVersion.startsWith("2.7")) return "5.3.20";
            return "6.2.1";
        }
        if (group.startsWith("org.apache.tomcat")) {
            if (bootVersion.startsWith("4.")) return "11.0.2";
            if (bootVersion.startsWith("3.")) return "10.1.34";
            if (bootVersion.startsWith("2.")) return "9.0.63";
            return "10.1.34";
        }
        if (group.equals("org.yaml") && artifact.equals("snakeyaml")) {
            return (bootVersion.startsWith("2.")) ? "1.30" : "2.2";
        }
        if (group.startsWith("ch.qos.logback")) {
            return (bootVersion.startsWith("2.")) ? "1.2.11" : "1.5.16";
        }
        if (group.startsWith("org.slf4j")) {
            return (bootVersion.startsWith("2.")) ? "1.7.36" : "2.0.16";
        }
        return null; // 독립 버전 체계의 서브 패키지는 가짜 버전을 부여하지 않아 오탐 차단
    }

    private void resolveGradleTransitiveFallback(Map<String, LLMAnalysisService.SbomPackageDetail> packagesMap) {
        boolean hasIndirect = packagesMap.values().stream().anyMatch(LLMAnalysisService.SbomPackageDetail::indirect);
        if (hasIndirect) {
            return;
        }

        String bootVersion = "3.4.1"; // 기본 안정화 Spring Boot 버전
        for (LLMAnalysisService.SbomPackageDetail p : packagesMap.values()) {
            if ((p.name().equals("org.springframework.boot") || p.name().contains("spring.boot") || p.name().contains("spring-boot"))
                    && !"(managed)".equals(p.version()) && !p.version().isBlank() && !p.version().equals("latest")) {
                bootVersion = p.version();
                break;
            }
        }

        // 1. (managed) 상태인 직접 의존성 중 Spring Boot 스타터 버전을 감지된 실제 bootVersion으로 동기화
        for (Map.Entry<String, LLMAnalysisService.SbomPackageDetail> entry : new ArrayList<>(packagesMap.entrySet())) {
            LLMAnalysisService.SbomPackageDetail p = entry.getValue();
            if (p.name().startsWith("org.springframework.boot:") && "(managed)".equals(p.version())) {
                packagesMap.put(p.name(), new LLMAnalysisService.SbomPackageDetail(p.name(), bootVersion, p.indirect(), p.license()));
            }
        }

        // 2. 주요 스타터 하위 전이 의존성을 버전 체계에 맞게 호환되는 정규 버전으로 안전 매핑
        List<LLMAnalysisService.SbomPackageDetail> directs = new ArrayList<>(packagesMap.values());
        for (LLMAnalysisService.SbomPackageDetail direct : directs) {
            List<String> children = COMMON_STARTER_CHILDREN.get(direct.name());
            if (children != null) {
                for (String child : children) {
                    String[] parts = child.split(":");
                    if (parts.length >= 2) {
                        String childVer = resolveCompatibleVersion(parts[0], parts[1], bootVersion);
                        if (childVer != null) {
                            packagesMap.putIfAbsent(child, new LLMAnalysisService.SbomPackageDetail(child, childVer, true, "Maven/Gradle"));
                        }
                    }
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
                    String childVer = (m.group(3) != null && !m.group(3).isBlank())
                            ? m.group(3).trim()
                            : resolveCompatibleVersion(childGroup, childArtifact, version);
                    if (childVer != null) {
                        String childFullName = childGroup + ":" + childArtifact;
                        map.putIfAbsent(childFullName, new LLMAnalysisService.SbomPackageDetail(childFullName, childVer, true, "Maven/Gradle"));
                    }
                }
            }
        } catch (Exception e) {
            log.debug("[UniversalScanner] Maven Central POM 보조 조회 스킵 ({}): {}", fullName, e.getMessage());
        }
    }

    private boolean resolveMavenViaWrapper(Path rootDir, Map<String, LLMAnalysisService.SbomPackageDetail> packagesMap) {
        if (!wrapperExecutionEnabled) {
            return false;
        }

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
                process.descendants().forEach(ProcessHandle::destroyForcibly);
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

    // =========================================================================
    // [Manifest-less 엔진] 소스코드 정밀 타격 의존성 추론 & 매니페스트 합성 구현체
    // =========================================================================

    private void inferAndSynthesizePython(Path rootDir, List<Path> files, Map<String, LLMAnalysisService.SbomPackageDetail> packagesMap) {
        Set<String> candidatePackages = new HashSet<>();
        for (Path file : files) {
            try (Stream<String> lines = Files.lines(file, StandardCharsets.UTF_8)) {
                lines.filter(l -> !l.isBlank() && l.length() <= 500)
                     .forEach(line -> {
                         String trimmed = line.trim();
                         if (trimmed.startsWith("import ") || trimmed.startsWith("from ")) {
                             Matcher m = PY_IMPORT_PATTERN.matcher(trimmed);
                             if (m.find()) {
                                 addPythonPackageCandidate(m.group(1), candidatePackages);
                             } else {
                                 m = PY_FROM_PATTERN.matcher(trimmed);
                                 if (m.find()) {
                                     addPythonPackageCandidate(m.group(1), candidatePackages);
                                 }
                             }
                         }
                     });
            } catch (Exception ignored) {}
        }

        if (candidatePackages.isEmpty()) {
            return;
        }

        log.info("[UniversalScanner] 🔍 [Manifest-less Python] 소스코드에서 {}개 서드파티 패키지 추출: {}",
                candidatePackages.size(), candidatePackages);
        Map<String, String> resolved = resolveVersionsAsync("pypi", candidatePackages);
        synthesizePythonRequirements(rootDir, resolved, packagesMap);
    }

    private void addPythonPackageCandidate(String mod, Set<String> candidates) {
        if (mod == null || mod.isBlank() || mod.startsWith(".")) {
            return;
        }
        String clean = mod.trim();
        if (clean.contains(".")) {
            clean = clean.split("\\.")[0].trim();
        }
        if (PYTHON_STDLIB.contains(clean.toLowerCase())) {
            return;
        }
        String pypiName = PYTHON_MODULE_TO_PKG.getOrDefault(clean, clean);
        candidates.add(pypiName);
    }

    private void synthesizePythonRequirements(Path rootDir, Map<String, String> resolvedPackages,
                                             Map<String, LLMAnalysisService.SbomPackageDetail> packagesMap) {
        Path reqFile = rootDir.resolve("requirements.txt");
        if (Files.exists(reqFile)) {
            return;
        }
        StringBuilder sb = new StringBuilder();
        sb.append("# Auto-generated by PR Guard for Manifest-less Python project\n");
        for (Map.Entry<String, String> entry : resolvedPackages.entrySet()) {
            String pkg = entry.getKey();
            String ver = entry.getValue();
            if (!"latest".equalsIgnoreCase(ver)) {
                sb.append(pkg).append("==").append(ver).append("\n");
            } else {
                sb.append(pkg).append("\n");
            }
            packagesMap.putIfAbsent(pkg, new LLMAnalysisService.SbomPackageDetail(pkg, ver, false, "PyPI(Python)"));
        }
        try {
            Files.writeString(reqFile, sb.toString(), StandardCharsets.UTF_8);
            log.info("[UniversalScanner] 🛡️ [Manifest-less] requirements.txt 자동 합성 생성 완료 (총 {}개 패키지)", resolvedPackages.size());
        } catch (IOException e) {
            log.warn("[UniversalScanner] requirements.txt 생성 실패: {}", e.getMessage());
        }
    }

    private void inferAndSynthesizeNode(Path rootDir, List<Path> files, Map<String, LLMAnalysisService.SbomPackageDetail> packagesMap) {
        Set<String> candidatePackages = new HashSet<>();
        for (Path file : files) {
            try (Stream<String> lines = Files.lines(file, StandardCharsets.UTF_8)) {
                lines.filter(l -> !l.isBlank() && l.length() <= 500)
                     .forEach(line -> {
                         if (line.contains("require(") || line.contains("import") || line.contains("export")) {
                             Matcher m = NODE_REQUIRE_PATTERN.matcher(line);
                             while (m.find()) {
                                 addNodePackageCandidate(m.group(1), candidatePackages);
                             }
                             m = NODE_IMPORT_PATTERN.matcher(line);
                             while (m.find()) {
                                 addNodePackageCandidate(m.group(1), candidatePackages);
                             }
                             m = NODE_BARE_IMPORT_PATTERN.matcher(line);
                             while (m.find()) {
                                 addNodePackageCandidate(m.group(1), candidatePackages);
                             }
                         }
                     });
            } catch (Exception ignored) {}
        }

        if (candidatePackages.isEmpty()) {
            return;
        }

        log.info("[UniversalScanner] 🔍 [Manifest-less Node.js] 소스코드에서 {}개 서드파티 패키지 추출: {}",
                candidatePackages.size(), candidatePackages);
        Map<String, String> resolved = resolveVersionsAsync("npm", candidatePackages);
        synthesizeNodePackageJson(rootDir, resolved, packagesMap);
    }

    private void addNodePackageCandidate(String specifier, Set<String> candidates) {
        String pkg = normalizeNpmPackageName(specifier);
        if (pkg != null && !pkg.isBlank()) {
            candidates.add(pkg);
        }
    }

    private String normalizeNpmPackageName(String raw) {
        if (raw == null || raw.isBlank()) return null;
        String trimmed = raw.trim();
        if (trimmed.startsWith(".") || trimmed.startsWith("/") || trimmed.startsWith("~") || trimmed.startsWith("@/")) {
            return null;
        }
        if (trimmed.startsWith("node:")) {
            return null;
        }
        if (NODE_BUILTINS.contains(trimmed)) {
            return null;
        }
        if (trimmed.startsWith("@")) {
            String[] parts = trimmed.split("/");
            if (parts.length >= 2) {
                return parts[0] + "/" + parts[1];
            }
            return trimmed;
        } else {
            int slash = trimmed.indexOf('/');
            if (slash > 0) {
                return trimmed.substring(0, slash);
            }
            return trimmed;
        }
    }

    private void synthesizeNodePackageJson(Path rootDir, Map<String, String> resolvedPackages,
                                          Map<String, LLMAnalysisService.SbomPackageDetail> packagesMap) {
        Path pkgJson = rootDir.resolve("package.json");
        if (Files.exists(pkgJson)) {
            return;
        }
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"name\": \"inferred-project\",\n");
        sb.append("  \"version\": \"1.0.0\",\n");
        sb.append("  \"description\": \"Auto-generated by PR Guard for Manifest-less project\",\n");
        sb.append("  \"dependencies\": {\n");
        int count = 0;
        int total = resolvedPackages.size();
        for (Map.Entry<String, String> entry : resolvedPackages.entrySet()) {
            count++;
            String pkg = entry.getKey();
            String ver = entry.getValue();
            String verStr = "latest".equalsIgnoreCase(ver) ? "*" : ver;
            sb.append("    \"").append(pkg).append("\": \"").append(verStr).append("\"");
            if (count < total) {
                sb.append(",");
            }
            sb.append("\n");
            packagesMap.putIfAbsent(pkg, new LLMAnalysisService.SbomPackageDetail(pkg, ver, false, "npm/Node.js"));
        }
        sb.append("  }\n");
        sb.append("}\n");
        try {
            Files.writeString(pkgJson, sb.toString(), StandardCharsets.UTF_8);
            log.info("[UniversalScanner] 🛡️ [Manifest-less] package.json 자동 합성 생성 완료 (총 {}개 패키지)", resolvedPackages.size());
        } catch (IOException e) {
            log.warn("[UniversalScanner] package.json 생성 실패: {}", e.getMessage());
        }
    }

    private void inferAndSynthesizeGo(Path rootDir, List<Path> files, Map<String, LLMAnalysisService.SbomPackageDetail> packagesMap) {
        Set<String> candidateModules = new HashSet<>();
        for (Path file : files) {
            try (Stream<String> lines = Files.lines(file, StandardCharsets.UTF_8)) {
                lines.filter(l -> !l.isBlank() && l.length() <= 500)
                     .forEach(line -> {
                         Matcher m = GO_IMPORT_LINE_PATTERN.matcher(line);
                         if (m.find()) {
                             String imp = m.group(1).trim();
                             if (imp.contains("/") && (imp.contains(".") || imp.startsWith("golang.org/") || imp.startsWith("google.golang.org/") || imp.startsWith("gopkg.in/"))) {
                                 String[] parts = imp.split("/");
                                 if (parts.length >= 3) {
                                     candidateModules.add(parts[0] + "/" + parts[1] + "/" + parts[2]);
                                 } else {
                                     candidateModules.add(imp);
                                 }
                             }
                         }
                     });
            } catch (Exception ignored) {}
        }

        if (candidateModules.isEmpty()) return;

        log.info("[UniversalScanner] 🔍 [Manifest-less Go] 소스코드에서 {}개 서드파티 모듈 추출: {}",
                candidateModules.size(), candidateModules);
        Map<String, String> resolved = resolveVersionsAsync("go", candidateModules);
        synthesizeGoMod(rootDir, resolved, packagesMap);
    }

    private void synthesizeGoMod(Path rootDir, Map<String, String> resolvedPackages,
                                Map<String, LLMAnalysisService.SbomPackageDetail> packagesMap) {
        Path goMod = rootDir.resolve("go.mod");
        if (Files.exists(goMod)) return;
        StringBuilder sb = new StringBuilder();
        sb.append("module inferred-project\n\ngo 1.21\n\nrequire (\n");
        for (Map.Entry<String, String> entry : resolvedPackages.entrySet()) {
            String pkg = entry.getKey();
            String ver = entry.getValue();
            String v = ver.startsWith("v") ? ver : ("v" + ver);
            if ("vlatest".equals(v)) v = "v1.0.0";
            sb.append("\t").append(pkg).append(" ").append(v).append("\n");
            packagesMap.putIfAbsent(pkg, new LLMAnalysisService.SbomPackageDetail(pkg, ver, false, "Go-Modules"));
        }
        sb.append(")\n");
        try {
            Files.writeString(goMod, sb.toString(), StandardCharsets.UTF_8);
            log.info("[UniversalScanner] 🛡️ [Manifest-less] go.mod 자동 합성 생성 완료 (총 {}개 패키지)", resolvedPackages.size());
        } catch (IOException e) {
            log.warn("[UniversalScanner] go.mod 생성 실패: {}", e.getMessage());
        }
    }

    private void inferAndSynthesizeRust(Path rootDir, List<Path> files, Map<String, LLMAnalysisService.SbomPackageDetail> packagesMap) {
        Set<String> candidateCrates = new HashSet<>();
        for (Path file : files) {
            try (Stream<String> lines = Files.lines(file, StandardCharsets.UTF_8)) {
                lines.filter(l -> !l.isBlank() && l.length() <= 500)
                     .forEach(line -> {
                         Matcher m = RUST_USE_PATTERN.matcher(line);
                         if (m.find()) {
                             addRustCrateCandidate(m.group(1), candidateCrates);
                         } else {
                             m = RUST_EXTERN_PATTERN.matcher(line);
                             if (m.find()) {
                                 addRustCrateCandidate(m.group(1), candidateCrates);
                             }
                         }
                     });
            } catch (Exception ignored) {}
        }

        if (candidateCrates.isEmpty()) return;

        log.info("[UniversalScanner] 🔍 [Manifest-less Rust] 소스코드에서 {}개 서드파티 크레이트 추출: {}",
                candidateCrates.size(), candidateCrates);
        Map<String, String> resolved = resolveVersionsAsync("cargo", candidateCrates);
        synthesizeCargoToml(rootDir, resolved, packagesMap);
    }

    private void addRustCrateCandidate(String name, Set<String> candidates) {
        if (name == null || name.isBlank()) return;
        String clean = name.trim();
        if (Set.of("std", "core", "alloc", "crate", "super", "self").contains(clean)) {
            return;
        }
        candidates.add(clean);
    }

    private void synthesizeCargoToml(Path rootDir, Map<String, String> resolvedPackages,
                                    Map<String, LLMAnalysisService.SbomPackageDetail> packagesMap) {
        Path cargoToml = rootDir.resolve("Cargo.toml");
        if (Files.exists(cargoToml)) return;
        StringBuilder sb = new StringBuilder();
        sb.append("[package]\nname = \"inferred-project\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\n");
        for (Map.Entry<String, String> entry : resolvedPackages.entrySet()) {
            String pkg = entry.getKey();
            String ver = entry.getValue();
            String verStr = "latest".equalsIgnoreCase(ver) ? "1.0" : ver;
            sb.append(pkg).append(" = \"").append(verStr).append("\"\n");
            packagesMap.putIfAbsent(pkg, new LLMAnalysisService.SbomPackageDetail(pkg, ver, false, "Crates.io(Rust)"));
        }
        try {
            Files.writeString(cargoToml, sb.toString(), StandardCharsets.UTF_8);
            log.info("[UniversalScanner] 🛡️ [Manifest-less] Cargo.toml 자동 합성 생성 완료 (총 {}개 패키지)", resolvedPackages.size());
        } catch (IOException e) {
            log.warn("[UniversalScanner] Cargo.toml 생성 실패: {}", e.getMessage());
        }
    }

    private void inferAndSynthesizeDotNet(Path rootDir, List<Path> files, Map<String, LLMAnalysisService.SbomPackageDetail> packagesMap) {
        Set<String> candidatePackages = new HashSet<>();
        for (Path file : files) {
            try (Stream<String> lines = Files.lines(file, StandardCharsets.UTF_8)) {
                lines.filter(l -> l.trim().startsWith("using ") && l.length() <= 500)
                     .forEach(line -> {
                         Matcher m = CS_USING_PATTERN.matcher(line);
                         if (m.find()) {
                             String ns = m.group(1).trim();
                             for (Map.Entry<String, String> entry : CS_NAMESPACE_TO_NUGET.entrySet()) {
                                 if (ns.equals(entry.getKey()) || ns.startsWith(entry.getKey() + ".")) {
                                     candidatePackages.add(entry.getValue());
                                 }
                             }
                         }
                     });
            } catch (Exception ignored) {}
        }

        if (candidatePackages.isEmpty()) return;

        log.info("[UniversalScanner] 🔍 [Manifest-less .NET/C#] 소스코드에서 {}개 NuGet 패키지 추출: {}",
                candidatePackages.size(), candidatePackages);
        Map<String, String> resolved = resolveVersionsAsync("nuget", candidatePackages);
        synthesizeCsproj(rootDir, resolved, packagesMap);
    }

    private void synthesizeCsproj(Path rootDir, Map<String, String> resolvedPackages,
                                 Map<String, LLMAnalysisService.SbomPackageDetail> packagesMap) {
        Path csproj = rootDir.resolve("InferredProject.csproj");
        if (Files.exists(csproj)) return;
        StringBuilder sb = new StringBuilder();
        sb.append("<Project Sdk=\"Microsoft.NET.Sdk\">\n");
        sb.append("  <PropertyGroup>\n    <TargetFramework>net8.0</TargetFramework>\n  </PropertyGroup>\n");
        sb.append("  <ItemGroup>\n");
        for (Map.Entry<String, String> entry : resolvedPackages.entrySet()) {
            String pkg = entry.getKey();
            String ver = entry.getValue();
            String verStr = "latest".equalsIgnoreCase(ver) ? "1.0.0" : ver;
            sb.append("    <PackageReference Include=\"").append(pkg).append("\" Version=\"").append(verStr).append("\" />\n");
            packagesMap.putIfAbsent(pkg, new LLMAnalysisService.SbomPackageDetail(pkg, ver, false, "NuGet"));
        }
        sb.append("  </ItemGroup>\n</Project>\n");
        try {
            Files.writeString(csproj, sb.toString(), StandardCharsets.UTF_8);
            log.info("[UniversalScanner] 🛡️ [Manifest-less] InferredProject.csproj 자동 합성 생성 완료 (총 {}개 패키지)", resolvedPackages.size());
        } catch (IOException e) {
            log.warn("[UniversalScanner] InferredProject.csproj 생성 실패: {}", e.getMessage());
        }
    }

    private void inferAndSynthesizeCpp(Path rootDir, List<Path> files, Map<String, LLMAnalysisService.SbomPackageDetail> packagesMap) {
        Set<String> candidatePackages = new HashSet<>();
        for (Path file : files) {
            try (Stream<String> lines = Files.lines(file, StandardCharsets.UTF_8)) {
                lines.filter(l -> l.trim().startsWith("#include") && l.length() <= 500)
                     .forEach(line -> {
                         Matcher m = CPP_INCLUDE_PATTERN.matcher(line);
                         if (m.find()) {
                             String header = m.group(1).trim();
                             for (Map.Entry<String, String> entry : CPP_HEADER_TO_PKG.entrySet()) {
                                 if (header.equals(entry.getKey()) || header.startsWith(entry.getKey() + "/") || header.startsWith(entry.getKey() + "\\")) {
                                     candidatePackages.add(entry.getValue());
                                 }
                             }
                         }
                     });
            } catch (Exception ignored) {}
        }

        if (candidatePackages.isEmpty()) return;

        log.info("[UniversalScanner] 🔍 [Manifest-less C/C++] 소스코드에서 {}개 라이브러리 추출: {}",
                candidatePackages.size(), candidatePackages);
        synthesizeVcpkgJson(rootDir, candidatePackages, packagesMap);
    }

    private void synthesizeVcpkgJson(Path rootDir, Set<String> packages,
                                    Map<String, LLMAnalysisService.SbomPackageDetail> packagesMap) {
        Path vcpkg = rootDir.resolve("vcpkg.json");
        if (Files.exists(vcpkg)) return;
        StringBuilder sb = new StringBuilder();
        sb.append("{\n  \"name\": \"inferred-project\",\n  \"version\": \"1.0.0\",\n  \"dependencies\": [\n");
        int count = 0;
        int total = packages.size();
        for (String pkg : packages) {
            count++;
            sb.append("    \"").append(pkg).append("\"");
            if (count < total) sb.append(",");
            sb.append("\n");
            packagesMap.putIfAbsent(pkg, new LLMAnalysisService.SbomPackageDetail(pkg, "system", false, "vcpkg(C/C++)"));
        }
        sb.append("  ]\n}\n");
        try {
            Files.writeString(vcpkg, sb.toString(), StandardCharsets.UTF_8);
            log.info("[UniversalScanner] 🛡️ [Manifest-less] vcpkg.json 자동 합성 생성 완료 (총 {}개 패키지)", packages.size());
        } catch (IOException e) {
            log.warn("[UniversalScanner] vcpkg.json 생성 실패: {}", e.getMessage());
        }
    }

    private void inferAndSynthesizeJava(Path rootDir, List<Path> files, Map<String, LLMAnalysisService.SbomPackageDetail> packagesMap) {
        Set<String> candidatePackages = new HashSet<>();
        for (Path file : files) {
            try (Stream<String> lines = Files.lines(file, StandardCharsets.UTF_8)) {
                lines.filter(l -> l.trim().startsWith("import ") && l.length() <= 500)
                     .forEach(line -> {
                         Matcher m = JAVA_IMPORT_PATTERN.matcher(line);
                         if (m.find()) {
                             String imp = m.group(1).trim();
                             for (Map.Entry<String, String> entry : JAVA_PREFIX_TO_PKG.entrySet()) {
                                 if (imp.startsWith(entry.getKey())) {
                                     candidatePackages.add(entry.getValue());
                                 }
                             }
                         }
                     });
            } catch (Exception ignored) {}
        }

        if (candidatePackages.isEmpty()) return;

        log.info("[UniversalScanner] 🔍 [Manifest-less Java/Kotlin] 소스코드에서 {}개 외부 라이브러리 추출: {}",
                candidatePackages.size(), candidatePackages);
        for (String pkg : candidatePackages) {
            packagesMap.putIfAbsent(pkg, new LLMAnalysisService.SbomPackageDetail(pkg, "latest", false, "Maven/Gradle"));
        }
        generateGradleLockfile(rootDir, packagesMap);
    }

    private Map<String, String> resolveVersionsAsync(String ecosystem, Set<String> packages) {
        Map<String, String> resultMap = new ConcurrentHashMap<>();
        if (packages == null || packages.isEmpty()) {
            return resultMap;
        }

        List<CompletableFuture<Void>> futures = new ArrayList<>();
        for (String pkg : packages) {
            futures.add(CompletableFuture.runAsync(() -> {
                String ver = fetchRegistryVersion(ecosystem, pkg);
                resultMap.put(pkg, ver);
            }));
        }

        try {
            CompletableFuture.allOf(futures.toArray(new CompletableFuture[0]))
                    .get(3, TimeUnit.SECONDS);
        } catch (Exception e) {
            log.warn("[UniversalScanner] {} 레지스트리 비동기 조회 타임아웃/경고: {}", ecosystem, e.getMessage());
        }

        for (String pkg : packages) {
            resultMap.putIfAbsent(pkg, "latest");
        }

        return resultMap;
    }

    private String fetchRegistryVersion(String ecosystem, String pkgName) {
        String cacheKey = ecosystem + ":" + pkgName;
        String cached = REGISTRY_VERSION_CACHE.get(cacheKey);
        if (cached != null) {
            return cached;
        }

        String version = "latest";
        try {
            HttpClient client = HttpClient.newBuilder()
                    .connectTimeout(Duration.ofMillis(1200))
                    .build();

            String pypiBase = cleanRegistryUrl(pypiRegistryUrl, "https://pypi.org/pypi");
            String npmBase = cleanRegistryUrl(npmRegistryUrl, "https://registry.npmjs.org");
            String cargoBase = cleanRegistryUrl(cargoRegistryUrl, "https://crates.io/api/v1/crates");
            String goBase = cleanRegistryUrl(goProxyUrl, "https://proxy.golang.org");
            String nugetBase = cleanRegistryUrl(nugetRegistryUrl, "https://azuresearch-usnc.nuget.org/query");

            String urlStr = switch (ecosystem) {
                case "pypi" -> pypiBase + "/" + pkgName + "/json";
                case "npm" -> npmBase + "/" + pkgName + "/latest";
                case "cargo" -> cargoBase + "/" + pkgName;
                case "go" -> goBase + "/" + pkgName.toLowerCase() + "/@latest";
                case "nuget" -> nugetBase + "?q=packageid:" + pkgName + "&take=1";
                default -> null;
            };

            if (urlStr != null) {
                HttpRequest.Builder reqBuilder = HttpRequest.newBuilder()
                        .uri(URI.create(urlStr))
                        .timeout(Duration.ofMillis(1500))
                        .GET();
                if ("cargo".equals(ecosystem)) {
                    reqBuilder.header("User-Agent", "PRGuard/1.0 (security-scanner)");
                }

                HttpResponse<String> resp = client.send(reqBuilder.build(), HttpResponse.BodyHandlers.ofString());
                if (resp.statusCode() == 200) {
                    JsonNode root = objectMapper.readTree(resp.body());
                    version = switch (ecosystem) {
                        case "pypi" -> root.path("info").path("version").asText("latest");
                        case "npm" -> root.path("version").asText("latest");
                        case "cargo" -> root.path("crate").path("max_version").asText("latest");
                        case "go" -> {
                            String v = root.path("Version").asText("latest");
                            yield v.startsWith("v") ? v.substring(1) : v;
                        }
                        case "nuget" -> {
                            JsonNode data = root.path("data");
                            if (data.isArray() && !data.isEmpty()) {
                                yield data.get(0).path("version").asText("latest");
                            }
                            yield "latest";
                        }
                        default -> "latest";
                    };
                }
            }
        } catch (Exception e) {
            log.debug("[UniversalScanner] Public Registry 버전 조회 스킵 ({}:{}): {}", ecosystem, pkgName, e.getMessage());
        }

        if (version.isBlank()) {
            version = "latest";
        }
        REGISTRY_VERSION_CACHE.put(cacheKey, version);
        return version;
    }
}

