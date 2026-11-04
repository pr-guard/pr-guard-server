package io.github.hanjungho.prguard.controller;

import io.github.hanjungho.prguard.dto.GithubWebhookPayload;
import io.github.hanjungho.prguard.service.SecurityScanPipeline;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/webhook")
public class WebhookController {

    private final SecurityScanPipeline securityScanPipeline;

    @PostMapping
    public ResponseEntity<String> receiveWebhook(@RequestBody GithubWebhookPayload payload) {
        String action = payload.getAction();
        Integer prNumber = payload.getNumber();
        String fullName = payload.getRepository() != null ? payload.getRepository().getFullName() : "N/A";
        String cloneUrl = payload.getRepository() != null ? payload.getRepository().getCloneUrl() : null;
        String branch = (payload.getPullRequest() != null && payload.getPullRequest().getHead() != null)
                ? payload.getPullRequest().getHead().getRef()
                : null;

        log.info("==================================================");
        log.info("[Webhook] GitHub Webhook 이벤트 수신: action={}, pr=#{}, repo={}, branch={}",
                action, prNumber, fullName, branch);
        log.info("==================================================");

        // 1. PR 생성 (opened) 또는 수정 커밋 푸시 (synchronize) 이벤트
        if (isTargetPrAction(action) && cloneUrl != null) {
            log.info("[Webhook] PR 대상 이벤트 감지 (PR #{}, action={}) - 비동기 보안 스캔 파이프라인 시작", prNumber, action);
            securityScanPipeline.executePipelineAsync(payload);
            return ResponseEntity.accepted().body("Security scan scheduled successfully");
        }

        // 2. ChatOps 댓글 재스캔 트리거 감지 (issue_comment: created)
        if ("created".equalsIgnoreCase(action) && payload.getIssue() != null && payload.getIssue().isPullRequest()) {
            if (payload.getComment() != null) {
                // 봇 자신이 남긴 코멘트(무한 루프 방지) 무시
                if (payload.getComment().getUser() != null && "Bot".equalsIgnoreCase(payload.getComment().getUser().getType())) {
                    log.info("[Webhook] Bot이 작성한 댓글이므로 스킵합니다.");
                    return ResponseEntity.ok("Ignored bot comment");
                }

                String commentBody = payload.getComment().getBody() != null ? payload.getComment().getBody().trim().toLowerCase() : "";
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
