package io.github.hanjungho.prguard.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.hanjungho.prguard.dto.GithubWebhookPayload;
import io.github.hanjungho.prguard.service.GitHubBotService;
import io.github.hanjungho.prguard.service.SecurityScanPipeline;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/api")
public class WebhookController {

    private final SecurityScanPipeline securityScanPipeline;
    private final GitHubBotService gitHubBotService;
    private final ObjectMapper objectMapper;

    @Value("${github.webhook.secret:}")
    private String webhookSecret;

    /**
     * Render 무료 티어 절전 모드(Sleep) 방지용 초경량 Health Check 엔드포인트
     */
    @GetMapping("/ping")
    public ResponseEntity<String> ping() {
        return ResponseEntity.ok("pong");
    }

    /**
     * GitHub Webhook 이벤트 수신 엔드포인트 (POST /api/webhook)
     * HMAC SHA-256 (X-Hub-Signature-256) 검증을 거쳐 위조된 요청을 원천 차단합니다.
     */
    @PostMapping("/webhook")
    public ResponseEntity<String> receiveWebhook(
            @RequestHeader(value = "X-Hub-Signature-256", required = false) String signatureHeader,
            @RequestBody byte[] rawPayload
    ) {
        // 1. Webhook HMAC SHA-256 서명 검증 (시크릿이 설정되어 있을 경우)
        if (webhookSecret != null && !webhookSecret.isBlank()) {
            if (signatureHeader == null || !signatureHeader.startsWith("sha256=")) {
                log.warn("[Webhook] 서명 헤더 누락 또는 비정상 형식: {}", signatureHeader);
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Missing or invalid X-Hub-Signature-256 header");
            }

            try {
                Mac mac = Mac.getInstance("HmacSHA256");
                SecretKeySpec secretKey = new SecretKeySpec(webhookSecret.trim().getBytes(StandardCharsets.UTF_8), "HmacSHA256");
                mac.init(secretKey);
                byte[] computedHash = mac.doFinal(rawPayload);
                String expectedSignature = "sha256=" + HexFormat.of().formatHex(computedHash);

                if (!MessageDigest.isEqual(expectedSignature.getBytes(StandardCharsets.UTF_8), signatureHeader.getBytes(StandardCharsets.UTF_8))) {
                    log.warn("[Webhook] HMAC 서명 불일치 (위조되거나 변조된 요청 차단)");
                    return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid HMAC signature");
                }
            } catch (Exception e) {
                log.error("[Webhook] HMAC 서명 검증 중 오류 발생: {}", e.getMessage());
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("HMAC verification failed");
            }
        }

        // 2. JSON 페이로드 역직렬화
        GithubWebhookPayload payload;
        try {
            payload = objectMapper.readValue(rawPayload, GithubWebhookPayload.class);
        } catch (Exception e) {
            log.error("[Webhook] 페이로드 역직렬화 실패: {}", e.getMessage());
            return ResponseEntity.badRequest().body("Invalid JSON payload");
        }

        String action = payload.getAction();
        Integer prNumber = payload.getNumber();
        String fullName = payload.getRepository() != null ? payload.getRepository().getFullName() : "N/A";

        // 오픈소스 Fork PR 지원: head.repo.clone_url 우선 추출 (외부 기여자 PR 지원)
        String cloneUrl = null;
        if (payload.getPullRequest() != null && payload.getPullRequest().getHead() != null && payload.getPullRequest().getHead().getRepo() != null) {
            cloneUrl = payload.getPullRequest().getHead().getRepo().getCloneUrl();
        }
        if (cloneUrl == null && payload.getRepository() != null) {
            cloneUrl = payload.getRepository().getCloneUrl();
        }

        String branch = (payload.getPullRequest() != null && payload.getPullRequest().getHead() != null)
                ? payload.getPullRequest().getHead().getRef()
                : null;

        log.info("==================================================");
        log.info("[Webhook] GitHub Webhook 이벤트 수신: action={}, pr=#{}, repo={}, branch={}",
                action, prNumber, fullName, branch);
        log.info("==================================================");

        // 3. PR 생성 (opened) 또는 수정 커밋 푸시 (synchronize) 이벤트
        if (isTargetPrAction(action) && cloneUrl != null) {
            log.info("[Webhook] PR 대상 이벤트 감지 (PR #{}, action={}) - 비동기 보안 스캔 파이프라인 시작", prNumber, action);
            securityScanPipeline.executePipelineAsync(payload);
            return ResponseEntity.accepted().body("Security scan scheduled successfully");
        }

        // 4. ChatOps 댓글 재스캔 트리거 감지 (issue_comment: created)
        if ("created".equalsIgnoreCase(action) && payload.getIssue() != null && payload.getIssue().isPullRequest()) {
            if (payload.getComment() != null) {
                // 봇 자신이 남긴 코멘트(무한 루프 방지) 무시
                if (payload.getComment().getUser() != null && "Bot".equalsIgnoreCase(payload.getComment().getUser().getType())) {
                    log.info("[Webhook] Bot이 작성한 댓글이므로 스킵합니다.");
                    return ResponseEntity.ok("Ignored bot comment");
                }

                String commentBody = payload.getComment().getBody() != null ? payload.getComment().getBody().trim().toLowerCase() : "";
                if (commentBody.contains("@prguard help") || commentBody.startsWith("/help")) {
                    Integer issuePrNumber = payload.getIssue().getNumber();
                    Long installationId = payload.getInstallation() != null ? payload.getInstallation().getId() : null;
                    log.info("[Webhook] ChatOps 도움말 명령어 감지! (Repo: {}, PR #{})", fullName, issuePrNumber);
                    String helpGuide = """
                            ### 🛡️ PR Guard 봇 사용 가이드
                            
                            PR Guard는 Pull Request에 대한 자동화된 보안 검증 및 취약점 통제를 수행합니다.
                            
                            **사용 가능한 명령어:**
                            - `@prguard rescan` 또는 `/rescan`: 현재 PR의 소스코드 및 의존성에 대한 보안 재스캔을 즉시 실행합니다.
                            - `@prguard help` 또는 `/help`: 이 도움말 메시지를 출력합니다.
                            
                            **제공 기능:**
                            - 🔍 **오픈소스 CVE 취약점 분석**: 알려진 보안 취약점 전수 검사 및 SBOM 인벤토리 제공
                            - 🔑 **하드코딩된 시크릿 노출 감지**: 코드 내 API 키/토큰 노출 시 해당 코드 라인에 인라인 경고 등록
                            - ⚙️ **보안 설정 결함(Misconfiguration) 탐지**: Dockerfile, K8s, 환경 설정 오류 감지
                            - 🤖 **Google Gemini AI 심층 판정**: 도달 가능성(Reachability) 분석 및 자동 PASS/WARN/BLOCK 판정
                            """;
                    gitHubBotService.postComment(fullName, issuePrNumber, installationId, helpGuide);
                    return ResponseEntity.ok("Help comment posted successfully");
                }

                if (commentBody.contains("@prguard rescan") || commentBody.startsWith("/rescan") || commentBody.contains("@prguard /rescan")) {
                    Integer issuePrNumber = payload.getIssue().getNumber();
                    log.info("[Webhook] ChatOps 재스캔 명령어 감지! (Repo: {}, PR #{}, Comment: '{}')", fullName, issuePrNumber, commentBody);
                    securityScanPipeline.executeRescanAsync(payload);
                    return ResponseEntity.accepted().body("Rescan command scheduled successfully");
                }
            }
        }

        log.info("[Webhook] 스캔 대상 이벤트가 아니므로 스킵합니다. (action={})", action);
        return ResponseEntity.ok("Ignored non-target action");
    }

    private boolean isTargetPrAction(String action) {
        return "opened".equalsIgnoreCase(action) || "synchronize".equalsIgnoreCase(action);
    }
}
