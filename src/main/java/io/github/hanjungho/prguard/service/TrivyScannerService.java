package io.github.hanjungho.prguard.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import io.github.hanjungho.prguard.dto.PrguardConfig;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.File;
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
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Stream;

@Slf4j
@Service
@RequiredArgsConstructor
public class TrivyScannerService {

    private final UniversalDependencyScanner universalDependencyScanner;

    public TrivyScannerService() {
        this.universalDependencyScanner = new UniversalDependencyScanner(new ObjectMapper());
    }

    @org.springframework.beans.factory.annotation.Value("${trivy.process.timeout-minutes:5}")
    private long processTimeoutMinutes = 5;

    @org.springframework.beans.factory.annotation.Value("${trivy.db.update-interval-hours:12}")
    private long dbUpdateIntervalHours = 12;

    @org.springframework.beans.factory.annotation.Value("${trivy.executable:}")
    private String configuredTrivyExecutable;

    private long getDbUpdateIntervalMs() {
        return Math.max(1, dbUpdateIntervalHours) * 60 * 60 * 1000L;
    }

    private long getProcessTimeoutMinutes() {
        return Math.max(1, processTimeoutMinutes);
    }

    /**
     * 저사양/무료 클라우드(512MB RAM)의 OOM(Out of Memory) 방지를 위한 동시 프로세스 제어 세마포어.
     * 한 번에 최대 1개의 무거운 프로세스(Git Clone + Trivy)만 동작하도록 격리합니다.
     */
    private final Semaphore heavyProcessSemaphore = new Semaphore(1, true);

    /**
     * 마지막 Trivy 취약점 DB 업데이트 타임스탬프 (12시간 이내 재스캔 시 --skip-db-update 적용)
     */
    private final AtomicLong lastDbUpdateTime = new AtomicLong(0L);

    /**
     * Trivy 스캔 JSON, 프로젝트 런타임/환경 설정 컨텍스트, .prguard.yml 커스텀 정책 및 범용 매니페스트 패키지 목록을 담는 반환 레코드
     */
    public record ScanResult(String scanJson, String runtimeContext, PrguardConfig config, List<LLMAnalysisService.SbomPackageDetail> manifestPackages) {
        public ScanResult(String scanJson, String runtimeContext, PrguardConfig config) {
            this(scanJson, runtimeContext, config, Collections.emptyList());
        }
    }

    public String scanRepository(String cloneUrl, String branch) {
        return scanRepositoryWithContext(cloneUrl, branch, null).scanJson();
    }

    public String scanRepository(String cloneUrl, String branch, String accessToken) {
        return scanRepositoryWithContext(cloneUrl, branch, accessToken).scanJson();
    }

    /**
     * 소스코드를 복제하고, .prguard.yml 정책 및 런타임 환경 설정 파일을 수집한 뒤 Trivy 종합 스캔을 수행합니다.
     */
    public ScanResult scanRepositoryWithContext(String cloneUrl, String branch, String accessToken) {
        Path tempDir = null;
        boolean semaphoreAcquired = false;
        try {
            // 저사양 서버 메모리(512MB RAM) 폭발 방지를 위한 세마포어 획득
            log.info("[TrivyScanner] 스캔 프로세스 실행을 위해 세마포어 대기 중...");
            heavyProcessSemaphore.acquire();
            semaphoreAcquired = true;
            log.info("[TrivyScanner] 세마포어 획득 성공 - 소스코드 Clone 및 Trivy 스캔 격리 실행 시작");

            // 1. UUID 기반 고유 임시 디렉토리 생성
            tempDir = Files.createTempDirectory("prguard-" + UUID.randomUUID());
            log.info("[TrivyScanner] 임시 디렉토리 생성 완료: {}", tempDir.toAbsolutePath());

            // 2. Git Clone 실행 (PR 대상 브랜치 명시 및 Private 저장소 토큰 지원)
            executeGitClone(cloneUrl, branch, tempDir, accessToken);

            // 3. 커스텀 보안 정책 파일(.prguard.yml) 탐색 및 파싱
            PrguardConfig prguardConfig = extractPrguardConfig(tempDir);

            // 4. 범용 매니페스트 스캐너 실행 (C++, C#, Unity, Unreal, Mobile, Flutter, Gradle 등 모든 생태계 직접 의존성 수집)
            List<LLMAnalysisService.SbomPackageDetail> manifestPackages = (universalDependencyScanner != null)
                    ? universalDependencyScanner.scan(tempDir)
                    : Collections.emptyList();
            log.info("[TrivyScanner] 범용 매니페스트 패키지 수집 완료: 총 {}개", manifestPackages.size());

            // 5. 런타임 환경 설정 컨텍스트 추출 (Dockerfile, .nvmrc, package.json, build.gradle 등)
            String runtimeContext = extractRuntimeContext(tempDir);
            log.info("[TrivyScanner] 런타임 환경 설정 컨텍스트 추출 완료 (길이: {}자)", runtimeContext.length());

            // 6. Trivy 취약점 스캔 실행 (stdout/stderr 캡처)
            String scanResult = executeTrivyScan(tempDir);
            log.info("[TrivyScanner] Trivy 스캔 완료");

            return new ScanResult(scanResult, runtimeContext, prguardConfig, manifestPackages);
        } catch (Exception e) {
            log.error("[TrivyScanner] 스캔 파이프라인 수행 실패: {}", e.getMessage(), e);
            throw new RuntimeException("Trivy 스캔 실패: " + e.getMessage(), e);
        } finally {
            // 6. 임시 디렉토리 완전 삭제
            if (tempDir != null) {
                deleteDirectoryRecursively(tempDir);
            }
            if (semaphoreAcquired) {
                heavyProcessSemaphore.release();
                log.info("[TrivyScanner] 세마포어 반환 완료");
            }
        }
    }

    /**
     * 프로젝트 루트에서 .prguard.yml 또는 .prguard.yaml 파일을 읽어 사용자 커스텀 보안 정책을 로드합니다.
     */
    public PrguardConfig extractPrguardConfig(Path rootDir) {
        Path configFile = rootDir.resolve(".prguard.yml");
        if (!Files.exists(configFile)) {
            configFile = rootDir.resolve(".prguard.yaml");
        }
        if (Files.exists(configFile) && Files.isRegularFile(configFile)) {
            try {
                ObjectMapper yamlMapper = new ObjectMapper(new YAMLFactory());
                String content = Files.readString(configFile, StandardCharsets.UTF_8);
                PrguardConfig config = yamlMapper.readValue(content, PrguardConfig.class);
                log.info("[TrivyScanner] 커스텀 보안 설정(.prguard.yml) 로드 성공: {}", config);
                return config;
            } catch (Exception e) {
                log.warn("[TrivyScanner] .prguard.yml 파싱 실패, 기본 설정을 적용합니다: {}", e.getMessage());
            }
        }
        return PrguardConfig.defaultConfig();
    }

    /**
     * 프로젝트 루트에서 런타임 및 기반 프레임워크 환경 설정 파일(Dockerfile, .nvmrc, package.json, build.gradle, pom.xml)을 추출합니다.
     */
    public String extractRuntimeContext(Path rootDir) {
        StringBuilder sb = new StringBuilder();

        // 1. .nvmrc / .node-version
        readAndAppendIfExists(rootDir, ".nvmrc", sb);
        readAndAppendIfExists(rootDir, ".node-version", sb);

        // 2. Dockerfile
        readAndAppendIfExists(rootDir, "Dockerfile", sb);
        readAndAppendIfExists(rootDir, "dockerfile", sb);

        // 3. package.json (engines, packageManager, dependencies 등 런타임/프레임워크 버전)
        Path packageJson = rootDir.resolve("package.json");
        if (Files.exists(packageJson) && Files.isRegularFile(packageJson)) {
            try {
                String content = Files.readString(packageJson, StandardCharsets.UTF_8);
                sb.append("--- [package.json (런타임 및 프레임워크 버전)] ---\n");
                if (content.length() <= 3000) {
                    sb.append(content.trim()).append("\n\n");
                } else {
                    sb.append(content.substring(0, 3000)).append("\n... (일부 생략)\n\n");
                }
            } catch (Exception ignored) {}
        }

        // 4. build.gradle / pom.xml
        Path buildGradle = rootDir.resolve("build.gradle");
        if (Files.exists(buildGradle) && Files.isRegularFile(buildGradle)) {
            try {
                String content = Files.readString(buildGradle, StandardCharsets.UTF_8);
                sb.append("--- [build.gradle (Java/Spring Boot 버전)] ---\n");
                if (content.length() <= 3000) {
                    sb.append(content.trim()).append("\n\n");
                } else {
                    sb.append(content.substring(0, 3000)).append("\n... (일부 생략)\n\n");
                }
            } catch (Exception ignored) {}
        }

        Path pomXml = rootDir.resolve("pom.xml");
        if (Files.exists(pomXml) && Files.isRegularFile(pomXml)) {
            try {
                String content = Files.readString(pomXml, StandardCharsets.UTF_8);
                sb.append("--- [pom.xml (Java/Spring Boot 버전)] ---\n");
                if (content.length() <= 3000) {
                    sb.append(content.trim()).append("\n\n");
                } else {
                    sb.append(content.substring(0, 3000)).append("\n... (일부 생략)\n\n");
                }
            } catch (Exception ignored) {}
        }

        if (sb.isEmpty()) {
            return "(탐지된 런타임/빌드 환경 설정 파일 없음)";
        }
        return sb.toString().trim();
    }

    private void readAndAppendIfExists(Path rootDir, String fileName, StringBuilder sb) {
        Path filePath = rootDir.resolve(fileName);
        if (Files.exists(filePath) && Files.isRegularFile(filePath)) {
            try {
                String content = Files.readString(filePath, StandardCharsets.UTF_8);
                sb.append("--- [").append(fileName).append("] ---\n");
                if (content.length() <= 2000) {
                    sb.append(content.trim()).append("\n\n");
                } else {
                    sb.append(content.substring(0, 2000)).append("\n... (생략)\n\n");
                }
            } catch (Exception ignored) {}
        }
    }

    public record ProcessRunResult(int exitCode, String output) {}

    /**
     * 외부 프로세스를 실행하고, 비동기 파이프로 출력을 안전하게 수집하며 타임아웃을 엄격히 강제합니다.
     * 동기식 스트림 읽기로 인한 데드락 및 프로세스 멈춤(Hang)을 원천 차단합니다.
     */
    private ProcessRunResult runProcessWithTimeout(ProcessBuilder processBuilder, long timeout, TimeUnit unit, String processName)
            throws IOException, InterruptedException {
        Process process = processBuilder.start();

        CompletableFuture<String> outputFuture = CompletableFuture.supplyAsync(() -> {
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
                StringBuilder sb = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    sb.append(line).append(System.lineSeparator());
                }
                return sb.toString();
            } catch (IOException e) {
                log.warn("[TrivyScanner] {} 프로세스 출력 스트림 읽기 중 오류: {}", processName, e.getMessage());
                return "";
            }
        });

        boolean finished = process.waitFor(timeout, unit);
        if (!finished) {
            process.descendants().forEach(ProcessHandle::destroyForcibly);
            process.destroyForcibly();
            outputFuture.cancel(true);
            throw new RuntimeException(processName + " 타임아웃 초과 (" + timeout + " " + unit.name().toLowerCase() + ")");
        }

        String output = "";
        try {
            output = outputFuture.get(5, TimeUnit.SECONDS);
        } catch (Exception e) {
            log.warn("[TrivyScanner] {} 프로세스 출력 완료 대기 중 예외: {}", processName, e.getMessage());
        }

        return new ProcessRunResult(process.exitValue(), output);
    }

    private void executeGitClone(String cloneUrl, String branch, Path targetDir, String accessToken) throws IOException, InterruptedException {
        log.info("[TrivyScanner] Git Clone 시작: {} (Branch: {})", cloneUrl, branch != null ? branch : "default");

        // GitHub Git HTTP 인증: x-access-token 기본 인증 URL 구성 (GitHub App 공식 지원)
        String targetCloneUrl = cloneUrl;
        boolean hasToken = accessToken != null && !accessToken.isBlank();
        if (hasToken && targetCloneUrl.startsWith("https://")) {
            targetCloneUrl = "https://x-access-token:" + accessToken + "@" + targetCloneUrl.substring("https://".length());
        }

        // 1차 시도: 브랜치 지정 + 액세스 토큰 URL Clone
        ProcessRunResult result = runGitCloneCmd(targetCloneUrl, branch, targetDir);

        // 2차 시도: 브랜치 미존재 등 오류 시, 토큰 인증을 유지한 채 기본 브랜치(default branch)로 재시도
        if (result.exitCode() != 0 && branch != null && !branch.isBlank()) {
            log.warn("[TrivyScanner] 브랜치({}) 지정 Clone 실패 (Exit code: {}). 토큰을 유지한 채 기본 브랜치로 재시도합니다.",
                    branch, result.exitCode());
            result = runGitCloneCmd(targetCloneUrl, null, targetDir);
        }

        // 3차 시도: 오픈소스 퍼블릭 Fork 저장소일 수 있으므로 무인증(Public) 원본 cloneUrl로 재시도
        if (result.exitCode() != 0 && hasToken) {
            log.warn("[TrivyScanner] 인증 토큰 Clone 실패 (Exit code: {}). 오픈소스 퍼블릭 저장소일 수 있으므로 무인증 Clone으로 재시도합니다.",
                    result.exitCode());
            result = runGitCloneCmd(cloneUrl, branch, targetDir);
            if (result.exitCode() != 0 && branch != null && !branch.isBlank()) {
                result = runGitCloneCmd(cloneUrl, null, targetDir);
            }
        }

        if (result.exitCode() != 0) {
            String sanitizedOutput = sanitizeToken(result.output().trim(), accessToken);
            log.error("[TrivyScanner] Git Clone 최종 실패 (Exit code: {}): {}",
                    result.exitCode(), sanitizedOutput);

            if (sanitizedOutput.contains("terminal prompts disabled") || sanitizedOutput.contains("could not read Username")
                    || sanitizedOutput.contains("Repository not found") || sanitizedOutput.contains("Authentication failed")) {
                throw new RuntimeException("Git Clone 실패 (비공개 저장소 접근 권한 부족): GitHub App 설정에서 Repository permissions -> 'Contents: Read' 권한을 활성화하고 저장소 소유자가 승인했는지 확인해주세요. (원문: " + sanitizedOutput + ")");
            }

            throw new RuntimeException("Git Clone 실패 (저장소 접근 권한 또는 브랜치 확인 필요): " + sanitizedOutput);
        }

        // Clone 완료 후 디렉토리가 실제로 채워졌는지 검증
        try (var stream = Files.list(targetDir)) {
            long fileCount = stream.count();
            if (fileCount == 0) {
                throw new IllegalStateException("Git Clone은 성공했으나 대상 디렉토리가 비어 있습니다: " + targetDir);
            }
            log.info("[TrivyScanner] Git Clone 성공 완료 (다운로드 항목 수: {}개)", fileCount);
        }
    }

    private String sanitizeToken(String text, String token) {
        if (text == null) return "";
        String sanitized = text;
        if (token != null && !token.isBlank()) {
            sanitized = sanitized.replace(token, "ghs_***");
        }
        return sanitized.replaceAll("ghs_[a-zA-Z0-9]+", "ghs_***");
    }

    private ProcessRunResult runGitCloneCmd(String cloneUrl, String branch, Path targetDir) throws IOException, InterruptedException {
        List<String> command = new ArrayList<>();
        command.add("git");
        command.add("-c");
        command.add("credential.helper="); // Git Credential Manager GUI 팝업 완전 차단
        command.add("clone");
        command.add("--depth");
        command.add("1");
        command.add("--no-tags");
        command.add("--single-branch");
        if (branch != null && !branch.isBlank()) {
            command.add("-b");
            command.add(branch);
        }
        command.add("--"); // Git 옵션 인젝션 방어 구분자
        command.add(cloneUrl);
        command.add(targetDir.toAbsolutePath().toString());

        ProcessBuilder processBuilder = new ProcessBuilder(command);
        processBuilder.environment().put("GIT_TERMINAL_PROMPT", "0");
        processBuilder.environment().put("GCM_INTERACTIVE", "never");
        processBuilder.redirectErrorStream(true);

        return runProcessWithTimeout(processBuilder, getProcessTimeoutMinutes(), TimeUnit.MINUTES, "Git Clone");
    }

    private String executeTrivyScan(Path scanTargetDir) throws IOException, InterruptedException {
        log.info("[TrivyScanner] Trivy 취약점 분석 실행");

        String trivyExecutable = resolveTrivyCommand();
        log.info("[TrivyScanner] 사용할 Trivy 바이너리 경로: {}", trivyExecutable);

        List<String> command = new ArrayList<>();
        command.add(trivyExecutable);
        command.add("fs");
        command.add("--format");
        command.add("json");
        command.add("--scanners");
        command.add("vuln,misconfig,secret");
        command.add("--list-all-pkgs");
        command.add("-q");
        command.add("--skip-dirs");
        command.add(".git,.gradle,gradle,build,target,bin,obj,node_modules,venv,__pycache__,.idea,.vscode");
        command.add("--timeout");
        command.add("2m");

        // Docker 이미지 빌드 시 Java DB가 이미 사전 내장되어 있으므로 런타임 100MB 재다운로드 원천 차단
        command.add("--skip-java-db-update");

        // 설정된 시간 주기 이내에 이미 최신 DB를 동기화했다면 네트워크 I/O 스킵하여 스캔 속도 3~5초 단축
        long now = System.currentTimeMillis();
        long lastUpdate = lastDbUpdateTime.get();
        boolean shouldSkipUpdate = (now - lastUpdate) < getDbUpdateIntervalMs() && lastUpdate > 0;

        if (shouldSkipUpdate) {
            log.info("[TrivyScanner] ⚡ 최근 {}시간 내 DB 업데이트 완료됨 -> --skip-db-update 및 --skip-java-db-update 적용 (스캔 시간 대폭 단축)", dbUpdateIntervalHours);
            command.add("--skip-db-update");
        } else {
            log.info("[TrivyScanner] 🔄 Trivy 취약점 DB 최신화 검사 수행 ({}시간 주기 갱신)", dbUpdateIntervalHours);
        }

        command.add(scanTargetDir.toAbsolutePath().toString());

        ProcessBuilder processBuilder = new ProcessBuilder(command);
        processBuilder.redirectErrorStream(true);

        ProcessRunResult result = runProcessWithTimeout(processBuilder, getProcessTimeoutMinutes(), TimeUnit.MINUTES, "Trivy Scan");
        String output = result.output();

        if (result.exitCode() != 0) {
            log.error("[TrivyScanner] Trivy 스캔 실패 (Exit code: {}):\n{}", result.exitCode(), output);
            throw new RuntimeException("Trivy 스캔 실패 (Exit code: " + result.exitCode() + ", 원인: " + output.trim() + ")");
        }

        // 스캔 성공 및 DB 업데이트 정상 완료 시 타임스탬프 갱신
        if (!shouldSkipUpdate) {
            lastDbUpdateTime.set(now);
            log.info("[TrivyScanner] Trivy 취약점 DB 최신화 완료 (타임스탬프 갱신 완료)");
        }

        return output;
    }

    private String resolveTrivyCommand() {
        if (configuredTrivyExecutable != null && !configuredTrivyExecutable.isBlank()) {
            return configuredTrivyExecutable.trim();
        }

        boolean isWindows = System.getProperty("os.name").toLowerCase().contains("win");
        if (!isWindows) {
            return "trivy";
        }

        try {
            Process p = new ProcessBuilder("where.exe", "trivy").start();
            if (p.waitFor() == 0) {
                return "trivy";
            }
        } catch (Exception ignored) {
        }

        String localAppData = System.getenv("LOCALAPPDATA");
        if (localAppData != null) {
            Path wingetLink = Path.of(localAppData, "Microsoft", "WinGet", "Links", "trivy.exe");
            if (Files.exists(wingetLink)) {
                return wingetLink.toAbsolutePath().toString();
            }

            Path wingetPackages = Path.of(localAppData, "Microsoft", "WinGet", "Packages");
            if (Files.exists(wingetPackages)) {
                try (Stream<Path> stream = Files.walk(wingetPackages, 3)) {
                    var trivyPath = stream
                            .filter(p -> p.getFileName().toString().equalsIgnoreCase("trivy.exe"))
                            .findFirst();
                    if (trivyPath.isPresent()) {
                        return trivyPath.get().toAbsolutePath().toString();
                    }
                } catch (Exception ignored) {
                }
            }
        }

        return "trivy";
    }

    private void deleteDirectoryRecursively(Path rootPath) {
        try {
            if (!Files.exists(rootPath)) {
                return;
            }
            Files.walkFileTree(rootPath, new SimpleFileVisitor<>() {
                @Override
                public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                    File f = file.toFile();
                    if (!f.canWrite()) {
                        f.setWritable(true);
                    }
                    Files.delete(file);
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult postVisitDirectory(Path dir, IOException exc) throws IOException {
                    Files.delete(dir);
                    return FileVisitResult.CONTINUE;
                }
            });
            log.info("[TrivyScanner] 임시 디렉토리 클린업 완료: {}", rootPath.toAbsolutePath());
        } catch (IOException e) {
            log.warn("[TrivyScanner] 임시 디렉토리 삭제 중 경고 발생: {}", e.getMessage());
        }
    }
}
