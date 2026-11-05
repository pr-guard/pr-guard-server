package io.github.hanjungho.prguard.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.io.InputStreamReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.time.Instant;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Stream;

@Slf4j
@Service
@RequiredArgsConstructor
public class GitHubBotService {

    private final ObjectMapper objectMapper;
    private final RestTemplate restTemplate;

    @Value("${github.app.id:}")
    private String appId;

    @Value("${github.app.private-key-path:}")
    private String privateKeyPath;

    @Value("${github.app.private-key:}")
    private String privateKeyContent;

    @Value("${github.app.default-installation-id:}")
    private String defaultInstallationId;

    @Value("${github.api.url:https://api.github.com}")
    private String githubApiUrl = "https://api.github.com";

    @Value("${github.check-run.name:PR Guard / Security Scan}")
    private String checkRunName = "PR Guard / Security Scan";

    @Value("${github.status.context:pr-guard/security}")
    private String statusContext = "pr-guard/security";

    @Value("${diff.max-length:15000}")
    private int maxDiffLength = 15000;

    private PrivateKey privateKey;

    /**
     * GitHub API 엔드포인트 URL을 동적으로 조합합니다 (GitHub Enterprise Server 완벽 호환)
     */
    public String apiUrl(String path) {
        String base = (githubApiUrl != null && !githubApiUrl.isBlank())
                ? githubApiUrl.replaceAll("/+$", "")
                : "https://api.github.com";
        String p = path.startsWith("/") ? path : "/" + path;
        return base + p;
    }

    /**
     * Installation Access Token 캐시용 레코드 (만료 5분 전까지 재사용)
     */
    private record CachedToken(String token, Instant expiresAt) {
        boolean isValid() {
            return Instant.now().isBefore(expiresAt.minusSeconds(300));
        }
    }

    private final Map<Long, CachedToken> tokenCache = new ConcurrentHashMap<>();

    /**
     * 서버 기동 시 .pem 파일(또는 환경변수 원시 텍스트)에서 Private Key를 1회 파싱하여 메모리에 캐싱합니다.
     * 외부 마운트 파일(/etc/secrets/...), 환경변수 직접 주입, 클래스패스 로드 및 디렉토리 자동 탐색을 모두 지원합니다.
     */
    @PostConstruct
    public void initPrivateKey() {
        try {
            java.io.Reader reader = findPrivateKeyReader();

            if (reader == null) {
                log.warn("[GitHubBot] ⚠️ GitHub App Private Key를 찾을 수 없습니다. " +
                        "GITHUB_APP_PRIVATE_KEY 환경변수, GITHUB_APP_PRIVATE_KEY_PATH 또는 *.pem 파일을 제공하세요.");
                return;
            }

            try (PEMParser pemParser = new PEMParser(reader)) {
                Object object = pemParser.readObject();
                JcaPEMKeyConverter converter = new JcaPEMKeyConverter();

                if (object instanceof PEMKeyPair keyPair) {
                    this.privateKey = converter.getPrivateKey(keyPair.getPrivateKeyInfo());
                } else if (object instanceof PrivateKeyInfo keyInfo) {
                    this.privateKey = converter.getPrivateKey(keyInfo);
                } else {
                    throw new IllegalArgumentException("지원하지 않는 PEM 포맷입니다: " + (object != null ? object.getClass().getName() : "null"));
                }
            }
            log.info("[GitHubBot] GitHub App Private Key 로드 완료 (App ID: {})", (appId != null && !appId.isBlank()) ? appId : "미지정");
        } catch (Exception e) {
            log.error("[GitHubBot] Private Key 로드 실패: {}", e.getMessage(), e);
            throw new IllegalStateException("GitHub App Private Key 로드에 실패했습니다.", e);
        }
    }

    private java.io.Reader findPrivateKeyReader() {
        // 1. 환경 변수로 직접 PEM 문자열이 주입된 경우 (Render 등 클라우드 배포 시 가장 간편)
        if (privateKeyContent != null && !privateKeyContent.isBlank() && privateKeyContent.contains("PRIVATE KEY")) {
            log.info("[GitHubBot] 환경 변수(GITHUB_APP_PRIVATE_KEY)에서 Private Key 직접 로드");
            return new java.io.StringReader(privateKeyContent.replace("\\n", "\n"));
        }

        // 2. 명시된 파일 경로 확인
        if (privateKeyPath != null && !privateKeyPath.isBlank()) {
            Path filePath = Path.of(privateKeyPath.trim());
            // 2-1. 외부 파일 시스템 경로 확인 (Render Secret File: /etc/secrets/...)
            if (Files.exists(filePath) && Files.isRegularFile(filePath)) {
                log.info("[GitHubBot] 외부 파일 시스템({})에서 Private Key 로드", filePath.toAbsolutePath());
                try {
                    return new InputStreamReader(Files.newInputStream(filePath), StandardCharsets.UTF_8);
                } catch (IOException e) {
                    log.warn("[GitHubBot] 지정된 Private Key 파일 읽기 실패: {}", e.getMessage());
                }
            }

            // 2-2. 클래스패스 확인 (로컬 개발 환경)
            ClassPathResource resource = new ClassPathResource(privateKeyPath.trim());
            if (resource.exists()) {
                log.info("[GitHubBot] 클래스패스({})에서 Private Key 로드", privateKeyPath);
                try {
                    return new InputStreamReader(resource.getInputStream(), StandardCharsets.UTF_8);
                } catch (IOException e) {
                    log.warn("[GitHubBot] 지정된 클래스패스 리소스 읽기 실패: {}", e.getMessage());
                }
            }
        }

        // 3. 스마트 자동 감지 (Auto-Discovery): 파일명이 바뀌어도 *.pem / *.key를 탐색
        // 3-1. 클라우드 시크릿 마운트 기본 경로 (/etc/secrets)
        java.io.Reader cloudReader = scanDirectoryForPem(Path.of("/etc/secrets"));
        if (cloudReader != null) return cloudReader;

        // 3-2. 로컬 소스 리소스 디렉토리 (src/main/resources)
        java.io.Reader srcReader = scanDirectoryForPem(Path.of("src/main/resources"));
        if (srcReader != null) return srcReader;

        // 3-3. 현재 작업 디렉토리 (.)
        java.io.Reader localReader = scanDirectoryForPem(Path.of("."));
        if (localReader != null) return localReader;

        return null;
    }

    private java.io.Reader scanDirectoryForPem(Path dir) {
        if (!Files.exists(dir) || !Files.isDirectory(dir)) {
            return null;
        }
        try (Stream<Path> stream = Files.list(dir)) {
            Optional<Path> pemFile = stream
                    .filter(Files::isRegularFile)
                    .filter(p -> {
                        String name = p.getFileName().toString().toLowerCase();
                        return (name.endsWith(".pem") || name.endsWith(".key"))
                                && !name.contains("public")
                                && !name.contains("cert");
                    })
                    .findFirst();

            if (pemFile.isPresent()) {
                Path found = pemFile.get();
                log.info("[GitHubBot] 🔑 Private Key 파일 자동 감지 성공: {}", found.toAbsolutePath());
                return new InputStreamReader(Files.newInputStream(found), StandardCharsets.UTF_8);
            }
        } catch (Exception e) {
            log.debug("[GitHubBot] 디렉토리 탐색 건너뜀 ({}): {}", dir, e.getMessage());
        }
        return null;
    }

    public static final String BOT_COMMENT_MARKER = "<!-- pr-guard-report-marker -->";

    /**
     * PR에 AI 분석 리포트를 코멘트로 작성하거나, 기존 리포트 코멘트가 존재할 경우 갱신(Upsert)합니다.
     * PR 댓글창이 수많은 봇 코멘트로 도배되는 현상(Spam)을 방지합니다.
     *
     * @param repoFullName   저장소 전체 이름 (예: "junghohans/test")
     * @param prNumber       PR 번호
     * @param installationId 웹훅 페이로드의 installation.id (없을 경우 자동 조회 또는 properties 설정값 사용)
     * @param commentBody    등록할 AI 분석 리포트 마크다운
     */
    public void postComment(String repoFullName, Integer prNumber, Long installationId, String commentBody) {
        log.info("[GitHubBot] PR 코멘트 등록/수정(Upsert) 파이프라인 시작 (Repo: {}, PR: #{})", repoFullName, prNumber);

        try {
            // 캐시 지원 토큰 획득
            String installationAccessToken = getInstallationAccessToken(repoFullName, installationId);

            String finalBody = (commentBody != null && commentBody.contains(BOT_COMMENT_MARKER))
                    ? commentBody
                    : BOT_COMMENT_MARKER + "\n\n" + (commentBody != null ? commentBody : "");

            Long existingCommentId = findExistingBotCommentId(repoFullName, prNumber, installationAccessToken);

            if (existingCommentId != null) {
                log.info("[GitHubBot] 기존 PR Guard 코멘트(ID: {}) 발견 - 내용을 최신 리포트로 갱신(PATCH)합니다.", existingCommentId);
                updateIssueComment(repoFullName, existingCommentId, installationAccessToken, finalBody);
                log.info("[GitHubBot] PR #{} 기존 코멘트(ID: {}) 갱신이 성공적으로 완료되었습니다.", prNumber, existingCommentId);
            } else {
                log.info("[GitHubBot] 기존 PR Guard 코멘트 없음 - 신규 코멘트(POST)를 작성합니다.");
                createIssueComment(repoFullName, prNumber, installationAccessToken, finalBody);
                log.info("[GitHubBot] PR #{} 에 신규 코멘트 등록이 성공적으로 완료되었습니다.", prNumber);
            }
        } catch (Exception e) {
            log.error("[GitHubBot] PR 코멘트 등록/수정 중 오류 발생: {}", e.getMessage(), e);
            throw new RuntimeException("GitHub PR 코멘트 작성/수정 실패: " + e.getMessage(), e);
        }
    }

    /**
     * AI 프롬프트 토큰 낭비 방지를 위한 보안 무관 파일 확장자 목록
     */
    private static final Set<String> IRRELEVANT_EXTENSIONS = Set.of(
            ".md", ".markdown", ".mdown", ".txt", ".rst", ".adoc",
            ".css", ".scss", ".sass", ".less", ".styl",
            ".svg", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".webp", ".bmp", ".tiff",
            ".woff", ".woff2", ".ttf", ".eot", ".otf",
            ".mp3", ".mp4", ".wav", ".avi", ".mov",
            ".csv", ".tsv", ".map", ".drawio"
    );

    /**
     * 런타임 보안과 무관한 정적 설정 파일명 목록
     */
    private static final Set<String> IRRELEVANT_FILENAMES = Set.of(
            ".gitignore", ".gitattributes", ".editorconfig", ".prettierrc", ".prettierignore",
            ".eslintignore", "license", "licence", "changelog", "changelog.md"
    );

    /**
     * GitHub PR Diff API를 호출하여 이번 PR에서 변경된 코드 Diff 텍스트를 조회합니다.
     * (Accept: application/vnd.github.v3.diff)
     * 보안 무관 파일(.md, .css, 이미지 등)을 사전에 필터링하여 LLM 입력 토큰을 최대 60~80% 절감합니다.
     * 프롬프트 및 토큰 초과를 방지하기 위해 최대 15,000자로 안전하게 Truncate합니다.
     */
    public String getPullRequestDiff(String repoFullName, Integer prNumber, Long installationId) {
        log.info("[GitHubBot] PR #{} Diff 수집 시작 (Repo: {})", prNumber, repoFullName);
        try {
            String token = getInstallationAccessToken(repoFullName, installationId);
            String url = apiUrl("/repos/" + repoFullName + "/pulls/" + prNumber);

            HttpHeaders headers = createAuthHeaders(token);
            headers.set("Accept", "application/vnd.github.v3.diff");

            ResponseEntity<String> response = restTemplate.exchange(url, HttpMethod.GET, new HttpEntity<>(headers), String.class);

            String diff = response.getBody();
            if (diff == null || diff.isBlank()) {
                log.info("[GitHubBot] PR #{} Diff 내용이 비어 있습니다.", prNumber);
                return "";
            }

            // 보안 무관 파일(.md, 스타일, 이미지 등) 블록 제거 (Diff 다이어트)
            String filteredDiff = filterSecurityRelevantDiff(diff);
            if (filteredDiff.isBlank()) {
                log.info("[GitHubBot] PR #{} 변경 파일이 모두 보안 무관 파일(문서/스타일/에셋)입니다.", prNumber);
                return "";
            }

            int maxLength = Math.max(1000, maxDiffLength);
            if (filteredDiff.length() > maxLength) {
                log.info("[GitHubBot] PR Diff 길이가 {}자이므로 최대 {}자로 잘라냅니다.", filteredDiff.length(), maxLength);
                return filteredDiff.substring(0, maxLength) + "\n\n... (Diff가 너무 길어 " + maxLength + "자 이후는 생략되었습니다)";
            }

            return filteredDiff;
        } catch (Exception e) {
            log.warn("[GitHubBot] PR Diff 조회 중 예외 발생 (Repo: {}, PR: #{}): {}", repoFullName, prNumber, e.getMessage());
            return "(PR Diff 수집 실패: " + e.getMessage() + ")";
        }
    }

    /**
     * Git Diff 텍스트를 파일 단위로 분할하여 보안과 무관한 파일(문서, 정적 이미지, 스타일시트 등)을 제외합니다.
     */
    public String filterSecurityRelevantDiff(String rawDiff) {
        if (rawDiff == null || rawDiff.isBlank()) {
            return "";
        }

        String[] fileDiffs = rawDiff.split("(?=diff --git )");
        StringBuilder relevantDiff = new StringBuilder();
        int skippedFiles = 0;
        int keptFiles = 0;

        for (String fileDiff : fileDiffs) {
            if (fileDiff.isBlank()) continue;

            String firstLine = fileDiff.lines().findFirst().orElse("");
            String filePath = extractFilePathFromDiffHeader(firstLine);

            if (isSecurityIrrelevantFile(filePath)) {
                skippedFiles++;
            } else {
                keptFiles++;
                relevantDiff.append(fileDiff);
            }
        }

        if (skippedFiles > 0) {
            log.info("[GitHubBot] ✂️ Diff 다이어트 적용: 보안 무관 파일 {}개 제외, 실행 코드/설정 파일 {}개 유지",
                    skippedFiles, keptFiles);
        }

        return relevantDiff.toString().trim();
    }

    private String extractFilePathFromDiffHeader(String headerLine) {
        if (headerLine == null || !headerLine.startsWith("diff --git ")) {
            return "";
        }
        int bIdx = headerLine.indexOf(" b/");
        if (bIdx != -1) {
            String path = headerLine.substring(bIdx + 3).trim();
            if (!path.startsWith("/dev/null")) {
                return path;
            }
        }
        int aIdx = headerLine.indexOf(" a/");
        if (aIdx != -1) {
            int endIdx = (bIdx > aIdx) ? bIdx : headerLine.length();
            return headerLine.substring(aIdx + 3, endIdx).trim();
        }
        return "";
    }

    private boolean isSecurityIrrelevantFile(String path) {
        if (path == null || path.isBlank()) return false;
        String lower = path.toLowerCase().trim();
        String filename = lower.contains("/") ? lower.substring(lower.lastIndexOf('/') + 1) : lower;

        if (IRRELEVANT_FILENAMES.contains(filename)) {
            return true;
        }
        for (String ext : IRRELEVANT_EXTENSIONS) {
            if (lower.endsWith(ext)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Installation Access Token을 조회합니다. 유효한 캐시가 존재하면 재사용하고, 없으면 신규 발급합니다.
     */
    public String getInstallationAccessToken(String repoFullName, Long payloadInstallationId) {
        String jwt = createJwt();
        Long targetInstallationId = resolveInstallationId(repoFullName, payloadInstallationId, jwt);

        CachedToken cached = tokenCache.get(targetInstallationId);
        if (cached != null && cached.isValid()) {
            log.info("[GitHubBot] 캐시된 Installation Access Token 재사용 (Installation ID: {})", targetInstallationId);
            return cached.token();
        }

        return fetchAndCacheInstallationAccessToken(targetInstallationId, jwt);
    }

    /**
     * GitHub App 인증용 JWT 토큰 생성 (RS256, 유효시간 10분)
     */
    public String createJwt() {
        if (privateKey == null) {
            throw new IllegalStateException("GitHub App Private Key가 로드되지 않았습니다. " +
                    "GITHUB_APP_PRIVATE_KEY 환경변수, GITHUB_APP_PRIVATE_KEY_PATH 또는 *.pem 파일을 설정하세요.");
        }
        if (appId == null || appId.isBlank()) {
            throw new IllegalStateException("GitHub App ID가 설정되지 않았습니다. GITHUB_APP_ID 환경변수를 설정하세요.");
        }

        long nowMillis = System.currentTimeMillis();
        Date issuedAt = new Date(nowMillis - (60 * 1000)); // 클럭 오차 방어 (1분 전)
        Date expiration = new Date(nowMillis + (10 * 60 * 1000)); // 10분 후 만료

        return Jwts.builder()
                .issuer(appId.trim())
                .issuedAt(issuedAt)
                .expiration(expiration)
                .signWith(privateKey, Jwts.SIG.RS256)
                .compact();
    }

    /**
     * Installation ID를 다단계로 해결합니다:
     * 1) 웹훅 페이로드에서 전달된 값
     * 2) 특정 저장소 전용 설치 조회 (GET /repos/{owner}/{repo}/installation - 멀티테넌트 환경 정확도 보장)
     * 3) application.properties 에 설정된 기본값
     * 4) GitHub API (/app/installations)를 통한 자동 감지 (단일 테넌트 fallback)
     */
    private Long resolveInstallationId(String repoFullName, Long payloadInstallationId, String jwt) {
        if (payloadInstallationId != null) {
            return payloadInstallationId;
        }

        // 1. repoFullName이 유효한 경우, 특정 저장소의 설치 정보를 직접 조회 (다중 테넌트 지원)
        if (repoFullName != null && !repoFullName.isBlank() && !"N/A".equalsIgnoreCase(repoFullName) && repoFullName.contains("/")) {
            try {
                String repoInstallUrl = apiUrl("/repos/" + repoFullName + "/installation");
                ResponseEntity<String> response = restTemplate.exchange(repoInstallUrl, HttpMethod.GET, createEmptyEntity(jwt), String.class);
                JsonNode repoInstallNode = objectMapper.readTree(response.getBody());
                long repoInstallId = repoInstallNode.path("id").asLong();
                if (repoInstallId > 0) {
                    log.info("[GitHubBot] 저장소({}) 전용 Installation ID 조회 성공: {}", repoFullName, repoInstallId);
                    return repoInstallId;
                }
            } catch (Exception e) {
                log.warn("[GitHubBot] 저장소별 Installation ID 조회 실패 (Repo: {}): {}", repoFullName, e.getMessage());
            }
        }

        if (defaultInstallationId != null && !defaultInstallationId.isBlank()) {
            return Long.parseLong(defaultInstallationId.trim());
        }

        log.info("[GitHubBot] Installation ID가 누락되어 GitHub API를 통해 설치 목록을 자동 조회합니다.");
        try {
            String url = apiUrl("/app/installations");
            ResponseEntity<String> response = restTemplate.exchange(url, HttpMethod.GET, createEmptyEntity(jwt), String.class);
            JsonNode installations = objectMapper.readTree(response.getBody());

            if (installations.isArray() && !installations.isEmpty()) {
                // 이 GitHub App이 설치된 첫 번째 계정/레포의 Installation ID 자동 획득
                Long autoId = installations.get(0).path("id").asLong();
                log.info("[GitHubBot] GitHub App 설치 ID 자동 감지 성공: {}", autoId);
                return autoId;
            }
        } catch (Exception e) {
            log.warn("[GitHubBot] Installation ID 자동 조회 실패: {}", e.getMessage());
        }

        throw new IllegalArgumentException(
                "Installation ID를 찾을 수 없습니다. GitHub App이 대상 계정/저장소에 'Install' 되어 있는지 확인하거나, " +
                "application.properties 에 github.app.default-installation-id 값을 지정하세요."
        );
    }

    /**
     * JWT를 사용하여 특정 Installation의 Access Token을 발급받고 메모리에 캐싱합니다.
     */
    private String fetchAndCacheInstallationAccessToken(Long installationId, String jwt) {
        String url = apiUrl("/app/installations/" + installationId + "/access_tokens");
        try {
            ResponseEntity<String> response = restTemplate.postForEntity(url, createJsonEntity(Map.of(), jwt), String.class);
            JsonNode rootNode = objectMapper.readTree(response.getBody());
            String token = rootNode.path("token").asText("");
            String expiresAtStr = rootNode.path("expires_at").asText("");

            if (token.isBlank()) {
                throw new IllegalStateException("응답에서 installation token을 찾을 수 없습니다: " + response.getBody());
            }

            Instant expiresAt = expiresAtStr.isBlank()
                    ? Instant.now().plusSeconds(3600)
                    : Instant.parse(expiresAtStr);

            tokenCache.put(installationId, new CachedToken(token, expiresAt));
            log.info("[GitHubBot] 신규 Installation Access Token 발급 및 캐싱 완료 (Installation ID: {}, 만료: {})",
                    installationId, expiresAt);

            return token;
        } catch (Exception e) {
            log.error("[GitHubBot] Installation Access Token 발급 실패 (ID: {}): {}", installationId, e.getMessage());
            throw new RuntimeException("Installation Access Token 획득 실패", e);
        }
    }

    /**
     * PR(Issue)에 코멘트를 등록합니다.
     */
    private void createIssueComment(String repoFullName, Integer prNumber, String accessToken, String commentBody) {
        String url = apiUrl("/repos/" + repoFullName + "/issues/" + prNumber + "/comments");
        try {
            HttpEntity<Map<String, String>> entity = createJsonEntity(Map.of("body", commentBody), accessToken);
            ResponseEntity<String> response = restTemplate.postForEntity(url, entity, String.class);
            if (!response.getStatusCode().is2xxSuccessful()) {
                throw new RuntimeException("코멘트 작성 실패: HTTP " + response.getStatusCode());
            }
        } catch (Exception e) {
            log.error("[GitHubBot] 코멘트 API 호출 실패 (Repo: {}, PR: #{}): {}", repoFullName, prNumber, e.getMessage());
            throw new RuntimeException("GitHub 코멘트 API 호출 실패", e);
        }
    }

    /**
     * PR에 이전에 등록된 PR Guard 봇 코멘트 ID를 검색합니다.
     */
    public Long findExistingBotCommentId(String repoFullName, Integer prNumber, String accessToken) {
        if (prNumber == null || repoFullName == null || repoFullName.isBlank() || "N/A".equals(repoFullName)) {
            return null;
        }

        try {
            String url = apiUrl("/repos/" + repoFullName + "/issues/" + prNumber + "/comments?per_page=100");
            ResponseEntity<String> response = restTemplate.exchange(url, HttpMethod.GET, createEmptyEntity(accessToken), String.class);
            JsonNode comments = objectMapper.readTree(response.getBody());

            if (comments.isArray()) {
                for (JsonNode comment : comments) {
                    String body = comment.path("body").asText("");
                    if (body.contains(BOT_COMMENT_MARKER) || body.contains("PR Guard 보안 분석 리포트") ||
                            (body.contains("PR Guard") && "Bot".equalsIgnoreCase(comment.path("user").path("type").asText("")))) {
                        return comment.path("id").asLong();
                    }
                }
            }
        } catch (Exception e) {
            log.warn("[GitHubBot] 기존 봇 코멘트 조회 중 예외 발생 (신규 등록 fallback): {}", e.getMessage());
        }
        return null;
    }

    /**
     * 기존 PR(Issue) 코멘트 내용을 갱신(PATCH)합니다.
     */
    private void updateIssueComment(String repoFullName, Long commentId, String accessToken, String commentBody) {
        String url = apiUrl("/repos/" + repoFullName + "/issues/comments/" + commentId);
        try {
            HttpEntity<Map<String, String>> entity = createJsonEntity(Map.of("body", commentBody), accessToken);
            ResponseEntity<String> response = restTemplate.exchange(url, HttpMethod.PATCH, entity, String.class);
            if (!response.getStatusCode().is2xxSuccessful()) {
                throw new RuntimeException("코멘트 수정 실패: HTTP " + response.getStatusCode());
            }
        } catch (Exception e) {
            log.error("[GitHubBot] 코멘트 수정 API 호출 실패 (Repo: {}, Comment ID: {}): {}", repoFullName, commentId, e.getMessage());
            throw new RuntimeException("GitHub 코멘트 수정 API 호출 실패", e);
        }
    }

    /**
     * PR 상세 정보 (브랜치명, 최신 커밋 SHA, Clone URL)
     */
    public record PullRequestDetails(String branch, String headSha, String cloneUrl) {}

    /**
     * GitHub PR 상세 API를 호출하여 브랜치, 최신 커밋 SHA, Clone URL을 조회합니다.
     */
    public PullRequestDetails getPullRequestDetails(String repoFullName, Integer prNumber, Long installationId) {
        log.info("[GitHubBot] PR #{} 상세 정보 조회 시작 (Repo: {})", prNumber, repoFullName);
        try {
            String token = getInstallationAccessToken(repoFullName, installationId);
            String url = apiUrl("/repos/" + repoFullName + "/pulls/" + prNumber);
            ResponseEntity<String> response = restTemplate.exchange(url, HttpMethod.GET, createEmptyEntity(token), String.class);

            JsonNode root = objectMapper.readTree(response.getBody());
            String branch = root.path("head").path("ref").asText("");
            String headSha = root.path("head").path("sha").asText("");
            String cloneUrl = root.path("head").path("repo").path("clone_url").asText("");
            if (cloneUrl.isBlank()) {
                cloneUrl = root.path("base").path("repo").path("clone_url").asText("");
            }

            log.info("[GitHubBot] PR #{} 상세 조회 성공: branch={}, sha={}", prNumber, branch, headSha);
            return new PullRequestDetails(branch, headSha, cloneUrl);
        } catch (Exception e) {
            log.error("[GitHubBot] PR 상세 정보 조회 실패 (Repo: {}, PR: #{}): {}", repoFullName, prNumber, e.getMessage());
            throw new RuntimeException("PR 상세 정보 조회 실패: " + e.getMessage(), e);
        }
    }

    /**
     * GitHub Checks API를 호출하여 'in_progress' 상태의 Check Run을 생성합니다.
     */
    public Long createCheckRun(String repoFullName, String headSha, Long installationId) {
        if (headSha == null || headSha.isBlank()) {
            log.warn("[GitHubBot] headSha가 없어 Check Run 생성을 건너뜁니다.");
            return null;
        }

        log.info("[GitHubBot] Check Run 생성 시작 (Repo: {}, SHA: {})", repoFullName, headSha);
        try {
            String token = getInstallationAccessToken(repoFullName, installationId);
            String url = apiUrl("/repos/" + repoFullName + "/check-runs");

            Map<String, Object> body = Map.of(
                    "name", (checkRunName != null && !checkRunName.isBlank()) ? checkRunName : "PR Guard / Security Scan",
                    "head_sha", headSha,
                    "status", "in_progress",
                    "started_at", Instant.now().toString(),
                    "output", Map.of(
                            "title", "보안 스캔 및 AI 분석 진행 중",
                            "summary", "Trivy 정적 분석 및 Gemini AI 보안 영향도 평가를 진행하고 있습니다..."
                    )
            );

            HttpEntity<Map<String, Object>> entity = createJsonEntity(body, token);
            ResponseEntity<String> response = restTemplate.postForEntity(url, entity, String.class);

            JsonNode root = objectMapper.readTree(response.getBody());
            Long checkRunId = root.path("id").asLong();
            log.info("[GitHubBot] Check Run 생성 완료 (ID: {})", checkRunId);
            return checkRunId;
        } catch (Exception e) {
            log.warn("[GitHubBot] Check Run 생성 중 오류 (권한 확인 필요: checks:write): {}", e.getMessage());
            return null;
        }
    }

    /**
     * Check Run 코드 라인별 어노테이션(Inline Annotation) 레코드
     */
    public record CheckRunAnnotation(
            String path,
            int startLine,
            int endLine,
            String annotationLevel,
            String title,
            String message,
            String rawDetails
    ) {
        public CheckRunAnnotation(String path, int line, String annotationLevel, String title, String message) {
            this(path, line, line, annotationLevel, title, message, null);
        }
    }

    /**
     * GitHub Checks API를 호출하여 Check Run 결과를 'completed' 상태로 업데이트합니다.
     *
     * @param conclusion success, failure, neutral, action_required
     */
    public void updateCheckRun(String repoFullName, Long checkRunId, Long installationId,
                               String conclusion, String title, String summary) {
        updateCheckRun(repoFullName, checkRunId, installationId, conclusion, title, summary, Collections.emptyList());
    }

    /**
     * GitHub Checks API를 호출하여 Check Run 결과 및 코드 라인별 Annotation을 'completed' 상태로 업데이트합니다.
     */
    public void updateCheckRun(String repoFullName, Long checkRunId, Long installationId,
                               String conclusion, String title, String summary,
                               List<CheckRunAnnotation> annotations) {
        if (checkRunId == null) {
            return;
        }

        log.info("[GitHubBot] Check Run 결과 업데이트 시작 (ID: {}, Conclusion: {}, Annotations: {}개)",
                checkRunId, conclusion, annotations != null ? annotations.size() : 0);
        try {
            String token = getInstallationAccessToken(repoFullName, installationId);
            String url = apiUrl("/repos/" + repoFullName + "/check-runs/" + checkRunId);

            Map<String, Object> outputMap = new LinkedHashMap<>();
            outputMap.put("title", title);
            outputMap.put("summary", summary);

            if (annotations != null && !annotations.isEmpty()) {
                // GitHub Checks API는 요청당 최대 50개의 annotations를 허용함
                List<Map<String, Object>> annotationList = annotations.stream()
                        .limit(50)
                        .map(a -> {
                            Map<String, Object> m = new LinkedHashMap<>();
                            m.put("path", a.path());
                            m.put("start_line", Math.max(1, a.startLine()));
                            m.put("end_line", Math.max(1, a.endLine()));
                            m.put("annotation_level", a.annotationLevel() != null ? a.annotationLevel() : "warning");
                            m.put("title", a.title() != null ? a.title() : "보안 알림");
                            m.put("message", a.message() != null ? a.message() : "보안 검증 주의 사항");
                            if (a.rawDetails() != null) {
                                m.put("raw_details", a.rawDetails());
                            }
                            return m;
                        })
                        .toList();
                outputMap.put("annotations", annotationList);
            }

            Map<String, Object> body = Map.of(
                    "name", (checkRunName != null && !checkRunName.isBlank()) ? checkRunName : "PR Guard / Security Scan",
                    "status", "completed",
                    "conclusion", conclusion,
                    "completed_at", Instant.now().toString(),
                    "output", outputMap
            );

            HttpEntity<Map<String, Object>> entity = createJsonEntity(body, token);
            restTemplate.exchange(url, HttpMethod.PATCH, entity, String.class);
            log.info("[GitHubBot] Check Run 결과 업데이트 완료 (ID: {})", checkRunId);
        } catch (Exception e) {
            log.warn("[GitHubBot] Check Run 결과 업데이트 실패: {}", e.getMessage());
        }
    }

    /**
     * PR 변경 코드의 특정 파일 및 라인에 인라인 리뷰 코멘트(Inline Diff Comment)를 작성합니다.
     * 1-Click 수정 제안(```suggestion) 블록을 지원하여 개발자가 버튼 하나로 취약점을 패치할 수 있도록 돕습니다.
     */
    public boolean postInlineReviewComment(String repoFullName, Integer prNumber, String commitSha,
                                          Long installationId, String filePath, int line, String commentBody) {
        if (prNumber == null || commitSha == null || filePath == null || filePath.isBlank() || line <= 0) {
            return false;
        }

        log.info("[GitHubBot] PR #{} 인라인 리뷰 코멘트 작성 시도 (파일: {}:{}, SHA: {})", prNumber, filePath, line, commitSha);
        try {
            String token = getInstallationAccessToken(repoFullName, installationId);
            String url = apiUrl("/repos/" + repoFullName + "/pulls/" + prNumber + "/comments");

            String cleanPath = filePath.startsWith("./") ? filePath.substring(2) : filePath;
            if (cleanPath.startsWith("/")) cleanPath = cleanPath.substring(1);

            Map<String, Object> body = Map.of(
                    "body", commentBody,
                    "commit_id", commitSha,
                    "path", cleanPath,
                    "line", line,
                    "side", "RIGHT"
            );

            HttpEntity<Map<String, Object>> entity = createJsonEntity(body, token);
            ResponseEntity<String> response = restTemplate.postForEntity(url, entity, String.class);
            boolean success = response.getStatusCode().is2xxSuccessful();
            if (success) {
                log.info("[GitHubBot] PR #{} 인라인 리뷰 코멘트 작성 성공 ({}:{})", prNumber, cleanPath, line);
            }
            return success;
        } catch (Exception e) {
            log.warn("[GitHubBot] PR #{} 인라인 리뷰 코멘트 작성 스킵 또는 실패 ({}:{}): {}",
                    prNumber, filePath, line, e.getMessage());
            return false;
        }
    }

    /**
     * 특정 커밋에 대해 GitHub Commit Status를 업데이트합니다. (엔터프라이즈 브랜치 보호 규칙 호환)
     *
     * @param state success, failure, pending, error
     */
    public void createCommitStatus(String repoFullName, String commitSha, Long installationId,
                                   String state, String description, String targetUrl) {
        if (commitSha == null || commitSha.isBlank() || repoFullName == null || repoFullName.isBlank()) {
            return;
        }

        log.info("[GitHubBot] 커밋 Status 업데이트 시도 (SHA: {}, State: {})", commitSha, state);
        try {
            String token = getInstallationAccessToken(repoFullName, installationId);
            String url = apiUrl("/repos/" + repoFullName + "/statuses/" + commitSha);

            Map<String, String> body = new HashMap<>();
            body.put("state", state);
            body.put("context", (statusContext != null && !statusContext.isBlank()) ? statusContext : "pr-guard/security");
            body.put("description", (description != null && description.length() > 140)
                    ? description.substring(0, 137) + "..."
                    : (description != null ? description : "PR Guard 보안 검증 결과"));
            if (targetUrl != null && !targetUrl.isBlank()) {
                body.put("target_url", targetUrl);
            }

            HttpEntity<Map<String, String>> entity = createJsonEntity(body, token);
            restTemplate.postForEntity(url, entity, String.class);
            log.info("[GitHubBot] 커밋 Status 업데이트 성공 (SHA: {}, State: {})", commitSha, state);
        } catch (Exception e) {
            log.warn("[GitHubBot] 커밋 Status 업데이트 실패 (SHA: {}): {}", commitSha, e.getMessage());
        }
    }

    /**
     * PR에 레이블을 추가합니다.
     */
    public void addLabel(String repoFullName, Integer prNumber, Long installationId, String label) {
        if (prNumber == null || label == null || label.isBlank()) {
            return;
        }
        log.info("[GitHubBot] PR #{} 에 레이블 추가 시도: {}", prNumber, label);
        try {
            String token = getInstallationAccessToken(repoFullName, installationId);
            String url = apiUrl("/repos/" + repoFullName + "/issues/" + prNumber + "/labels");

            HttpEntity<Map<String, Object>> entity = createJsonEntity(Map.of("labels", List.of(label)), token);
            restTemplate.postForEntity(url, entity, String.class);
            log.info("[GitHubBot] PR #{} 에 레이블 추가 성공: {}", prNumber, label);
        } catch (Exception e) {
            log.warn("[GitHubBot] 레이블 추가 실패: {}", e.getMessage());
        }
    }

    /**
     * PR에서 특정 레이블을 제거합니다. (없을 경우 404 무시)
     */
    public void removeLabel(String repoFullName, Integer prNumber, Long installationId, String label) {
        if (prNumber == null || label == null || label.isBlank()) {
            return;
        }
        log.info("[GitHubBot] PR #{} 에서 레이블 제거 시도: {}", prNumber, label);
        try {
            String token = getInstallationAccessToken(repoFullName, installationId);
            String url = apiUrl("/repos/" + repoFullName + "/issues/" + prNumber + "/labels/" + label);

            restTemplate.exchange(url, HttpMethod.DELETE, createEmptyEntity(token), Void.class);
            log.info("[GitHubBot] PR #{} 에서 레이블 제거 성공: {}", prNumber, label);
        } catch (Exception e) {
            // 404 Not Found는 라벨이 이미 없는 정상 케이스이므로 info 레벨 로깅
            log.debug("[GitHubBot] 레이블 제거 스킵 (이미 없거나 제거됨): {}", e.getMessage());
        }
    }

    /**
     * 댓글(Issue Comment)에 이모지 반응(Reaction)을 남깁니다. (예: "eyes", "+1")
     */
    public void addReaction(String repoFullName, Long commentId, Long installationId, String content) {
        if (commentId == null || content == null || content.isBlank()) {
            return;
        }
        try {
            String token = getInstallationAccessToken(repoFullName, installationId);
            String url = apiUrl("/repos/" + repoFullName + "/issues/comments/" + commentId + "/reactions");

            HttpEntity<Map<String, String>> entity = createJsonEntity(Map.of("content", content), token);
            restTemplate.postForEntity(url, entity, String.class);
            log.info("[GitHubBot] 댓글 #{} 에 반응 추가 완료: {}", commentId, content);
        } catch (Exception e) {
            log.warn("[GitHubBot] 댓글 반응 추가 실패: {}", e.getMessage());
        }
    }

    /**
     * GitHub PR Review를 공식 제출합니다 (APPROVE, REQUEST_CHANGES, COMMENT).
     * 브랜치 보호 규칙의 'Require review from Pull Request' 정책과 완벽 연동됩니다.
     */
    public void submitPullRequestReview(String repoFullName, Integer prNumber, String commitSha,
                                       Long installationId, String event, String bodyText) {
        if (prNumber == null || commitSha == null || repoFullName == null) {
            return;
        }

        log.info("[GitHubBot] PR #{} 공식 리뷰 제출 시도 (이벤트: {}, SHA: {})", prNumber, event, commitSha);
        try {
            String token = getInstallationAccessToken(repoFullName, installationId);
            String url = apiUrl("/repos/" + repoFullName + "/pulls/" + prNumber + "/reviews");

            Map<String, String> body = Map.of(
                    "commit_id", commitSha,
                    "event", event,
                    "body", bodyText != null ? bodyText : "PR Guard 보안 검증 완료"
            );

            HttpEntity<Map<String, String>> entity = createJsonEntity(body, token);
            restTemplate.postForEntity(url, entity, String.class);
            log.info("[GitHubBot] PR #{} 공식 리뷰 제출 성공 (이벤트: {})", prNumber, event);
        } catch (Exception e) {
            // 자신의 PR을 리뷰할 수 없거나 이미 닫힌 경우(422) 안전하게 로깅 후 통과
            log.warn("[GitHubBot] PR #{} 공식 리뷰 제출 스킵/실패 (이벤트: {}): {}", prNumber, event, e.getMessage());
        }
    }

    private HttpHeaders createBaseHeaders() {
        HttpHeaders headers = new HttpHeaders();
        headers.set("Accept", "application/vnd.github+json");
        headers.set("X-GitHub-Api-Version", "2022-11-28");
        return headers;
    }

    private HttpHeaders createAuthHeaders(String token) {
        HttpHeaders headers = createBaseHeaders();
        if (token != null && !token.isBlank()) {
            headers.setBearerAuth(token);
        }
        return headers;
    }

    private HttpHeaders createJsonAuthHeaders(String token) {
        HttpHeaders headers = createAuthHeaders(token);
        headers.setContentType(MediaType.APPLICATION_JSON);
        return headers;
    }

    private <T> HttpEntity<T> createJsonEntity(T body, String token) {
        return new HttpEntity<>(body, createJsonAuthHeaders(token));
    }

    private HttpEntity<Void> createEmptyEntity(String token) {
        return new HttpEntity<>(createAuthHeaders(token));
    }
}
