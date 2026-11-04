package io.github.hanjungho.prguard.service;

import io.github.hanjungho.prguard.dto.GithubWebhookPayload;
import io.github.hanjungho.prguard.dto.PrguardConfig;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import java.util.concurrent.ConcurrentHashMap;

@Slf4j
@Service
@RequiredArgsConstructor
public class SecurityScanPipeline {

    private final TrivyScannerService trivyScannerService;
    private final LLMAnalysisService llmAnalysisService;
    private final GitHubBotService gitHubBotService;

    /**
     * 현재 스캔이 진행 중인 PR 추적 맵 (연속 푸시로 인한 중복 스캔 방지)
     * Key: "repoFullName#prNumber", Value: "headSha"
     */
    private final ConcurrentHashMap<String, String> activeScans = new ConcurrentHashMap<>();

    /**
     * 최근 스캔이 완료된 커밋 추적 맵 (네트워크 재전송 등 동일 커밋 중복 웹훅 방지)
     * Key: "repoFullName#prNumber@headSha", Value: 완료 타임스탬프
     */
    private final ConcurrentHashMap<String, Long> recentCompletedScans = new ConcurrentHashMap<>();
    private static final long DEDUP_WINDOW_MS = 10 * 60 * 1000L; // 10분 이내 중복 스캔 차단

    /**
     * PR opened 또는 synchronize(커밋 푸시) 이벤트 수신 시 비동기 스캔 실행
     */
    @Async("scanTaskExecutor")
    public void executePipelineAsync(GithubWebhookPayload payload) {
        Integer prNumber = payload.getNumber();
        String fullName = payload.getRepository() != null ? payload.getRepository().getFullName() : "N/A";
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
        String headSha = (payload.getPullRequest() != null && payload.getPullRequest().getHead() != null)
                ? payload.getPullRequest().getHead().getSha()
                : null;
        Long installationId = payload.getInstallation() != null ? payload.getInstallation().getId() : null;

        log.info("[Pipeline] PR 이벤트 수신 - 비동기 보안 분석 시작 (PR #{}, Repo: {}, Branch: {}, CloneUrl: {})",
                prNumber, fullName, branch, cloneUrl);
        runScanPipeline(fullName, prNumber, cloneUrl, branch, headSha, installationId);
    }

    /**
     * 댓글(Issue Comment)에 '@prguard rescan' 등 재스캔 명령어가 입력되었을 때 비동기 재스캔 실행
     */
    @Async("scanTaskExecutor")
    public void executeRescanAsync(GithubWebhookPayload payload) {
        String fullName = payload.getRepository() != null ? payload.getRepository().getFullName() : "N/A";
        Integer prNumber = payload.getIssue() != null ? payload.getIssue().getNumber() : null;
        Long installationId = payload.getInstallation() != null ? payload.getInstallation().getId() : null;
        Long commentId = payload.getComment() != null ? payload.getComment().getId() : null;

        log.info("[Pipeline] ChatOps 재스캔 요청 수신 (PR #{}, Repo: {})", prNumber, fullName);

        // 1. 개발자 명령어에 즉각적인 확인(Acknowledge) 반응(👀) 추가
        if (commentId != null) {
            gitHubBotService.addReaction(fullName, commentId, installationId, "eyes");
        }

        try {
            // 2. PR 최신 상태(브랜치명, 최신 commit sha, clone url) 조회
            GitHubBotService.PullRequestDetails prDetails = gitHubBotService.getPullRequestDetails(fullName, prNumber, installationId);
            runScanPipeline(fullName, prNumber, prDetails.cloneUrl(), prDetails.branch(), prDetails.headSha(), installationId);
        } catch (Exception e) {
            log.error("[Pipeline] ChatOps 재스캔 준비 실패 (PR #{}, Repo: {}): {}", prNumber, fullName, e.getMessage(), e);
            sendFailureFeedbackComment(fullName, prNumber, installationId, e);
        }
    }

    /**
     * 전체 보안 분석, AI 평가, GitHub Checks 및 레이블 관리 파이프라인
     */
    private void runScanPipeline(String fullName, Integer prNumber, String cloneUrl, String branch, String headSha, Long installationId) {
        Long checkRunId = null;

        // 0. 최신 commit sha가 없으면 PR 상세 조회로 보완
        if (headSha == null || headSha.isBlank()) {
            try {
                GitHubBotService.PullRequestDetails details = gitHubBotService.getPullRequestDetails(fullName, prNumber, installationId);
                headSha = details.headSha();
                if (cloneUrl == null) cloneUrl = details.cloneUrl();
                if (branch == null) branch = details.branch();
            } catch (Exception ignored) {}
        }

        String prKey = fullName + "#" + prNumber;
        String commitKey = (headSha != null) ? prKey + "@" + headSha : null;

        // 1. 최근 10분 내 동일 커밋 스캔 완료 여부 검사 (중복 웹훅 차단)
        if (commitKey != null) {
            Long lastCompletedTime = recentCompletedScans.get(commitKey);
            if (lastCompletedTime != null && (System.currentTimeMillis() - lastCompletedTime) < DEDUP_WINDOW_MS) {
                log.info("[Pipeline] ⏭️ 동일 커밋(SHA: {})에 대한 스캔이 최근 이미 완료되었습니다. 중복 스캔 생략 (Repo: {}, PR #{})",
                        headSha, fullName, prNumber);
                return;
            }
        }

        // 2. 동일 PR에 대한 진행 중인 스캔 중복 제어 (연속 푸시 방어)
        String runningSha = activeScans.putIfAbsent(prKey, headSha != null ? headSha : "UNKNOWN");
        if (runningSha != null) {
            log.warn("[Pipeline] ⚠️ PR #{} 에 대한 스캔이 이미 진행 중입니다 (진행 중 SHA: {}, 신규 요청 SHA: {}). 중복 파이프라인 방지.",
                    prNumber, runningSha, headSha);
            return;
        }

        try {
            // 1. GitHub Checks API를 호출하여 'PR Guard / Security Scan' 진행 중(in_progress) 등록
            checkRunId = gitHubBotService.createCheckRun(fullName, headSha, installationId);

            // 2. Private 저장소 복제 및 인증을 위한 Installation Access Token 획득 (캐시 적용)
            String accessToken = gitHubBotService.getInstallationAccessToken(fullName, installationId);

            // 3. PR 코드 Diff 수집을 비동기 병렬로 시작 (소스코드 Clone 및 Trivy 스캔과 동시 수행하여 지연 최소화)
            log.info("[Pipeline] Step 1: PR #{} 코드 Diff 수집 및 Trivy 스캔 비동기 병렬 시작", prNumber);
            java.util.concurrent.CompletableFuture<String> prDiffFuture = java.util.concurrent.CompletableFuture.supplyAsync(
                    () -> gitHubBotService.getPullRequestDiff(fullName, prNumber, installationId)
            );

            // 4. PR 대상 소스코드 Clone, .prguard.yml 커스텀 정책 로드, 런타임 환경 설정 수집 및 Trivy 스캔
            log.info("[Pipeline] Step 2: Trivy 종합 보안 스캔 및 커스텀 정책 로드 실행");
            TrivyScannerService.ScanResult scanResult = trivyScannerService.scanRepositoryWithContext(cloneUrl, branch, accessToken);
            String scanResultJson = scanResult.scanJson();
            String runtimeContext = scanResult.runtimeContext();
            PrguardConfig prguardConfig = scanResult.config();
            log.info("[Pipeline] Trivy 스캔 완료 (수집 데이터: {} KB, 런타임: {}자, 커스텀 정책: {})",
                    scanResultJson.length() / 1024, runtimeContext.length(), prguardConfig.toSummaryString());

            // 5. 비동기로 동시 수집 중이던 PR Diff 결과 회수
            String prDiff = prDiffFuture.join();

            // 5. 커스텀 정책 기반 필터링 및 Gemini AI 종합 보안/런타임 영향도 분석 (캐시 & Short-Circuit 및 범용 매니페스트 통합)
            log.info("[Pipeline] Step 3: Gemini AI 종합 보안 분석 진행 중... (매니페스트 추출 패키지: {}개)",
                    scanResult.manifestPackages() != null ? scanResult.manifestPackages().size() : 0);
            LLMAnalysisService.AnalysisOutcome outcome = llmAnalysisService.analyzeVulnerabilities(
                    scanResultJson, prDiff, runtimeContext, prguardConfig, scanResult.manifestPackages());

            String aiAnalysisReport = outcome.reportMarkdown();
            LLMAnalysisService.SecurityVerdict verdict = outcome.verdict();
            log.info("[Pipeline] AI 보안 분석 완료 - 최종 판정: {}", verdict);

            // 6. GitHub PR에 Bot 리포트 코멘트 등록
            log.info("[Pipeline] Step 4: GitHub PR #{} 에 통합 분석 리포트 코멘트 등록", prNumber);
            gitHubBotService.postComment(fullName, prNumber, installationId, aiAnalysisReport.trim());

            // 7. GitHub Checks API 및 PR Labels 상태 동기화 (Merge 차단 통제)
            applySecurityVerdictToGitHub(fullName, prNumber, checkRunId, installationId, verdict);

            log.info("[Pipeline] 비동기 보안 분석 및 통제 파이프라인 완료 (PR #{}, Repo: {}, Verdict: {})", prNumber, fullName, verdict);

        } catch (Exception e) {
            log.error("[Pipeline] 보안 분석 및 코멘트 파이프라인 수행 실패 (PR #{}, Repo: {}): {}",
                    prNumber, fullName, e.getMessage(), e);

            // Checks API 오류 마킹
            if (checkRunId != null) {
                gitHubBotService.updateCheckRun(fullName, checkRunId, installationId,
                        "action_required",
                        "스캔 실패: 일시적 오류 발생",
                        "보안 분석 파이프라인 실행 중 오류가 발생했습니다: " + e.getMessage());
            }

            // 에러 발생 시 PR에 안내 코멘트 등록 (Silent Failure 방지 Fallback)
            if (prNumber != null && !"N/A".equals(fullName)) {
                sendFailureFeedbackComment(fullName, prNumber, installationId, e);
            }
        } finally {
            activeScans.remove(prKey);
            if (commitKey != null) {
                recentCompletedScans.put(commitKey, System.currentTimeMillis());
            }
            cleanupExpiredCompletedScans();
        }
    }

    private void cleanupExpiredCompletedScans() {
        if (recentCompletedScans.size() > 200) {
            long threshold = System.currentTimeMillis() - DEDUP_WINDOW_MS;
            recentCompletedScans.entrySet().removeIf(entry -> entry.getValue() < threshold);
        }
    }

    /**
     * 최종 판정(BLOCK / WARN / PASS)에 따라 GitHub Checks API 결과 업데이트 및 security-risk 라벨 관리
     */
    private void applySecurityVerdictToGitHub(String fullName, Integer prNumber, Long checkRunId,
                                             Long installationId, LLMAnalysisService.SecurityVerdict verdict) {
        switch (verdict) {
            case BLOCK -> {
                // Merge 차단(failure) 및 security-risk 라벨 부착
                gitHubBotService.updateCheckRun(fullName, checkRunId, installationId,
                        "failure",
                        "차단 권고 (BLOCK): 심각한 보안 위험 검출",
                        "고위험 취약점 또는 코드 내 보안 결함이 검출되어 병합(Merge)이 차단되었습니다. PR 코멘트의 즉시 조치 가이드를 확인해 주세요.");
                gitHubBotService.addLabel(fullName, prNumber, installationId, "security-risk");
            }
            case WARN -> {
                // 경고(neutral) 및 security-risk 라벨 제거
                gitHubBotService.updateCheckRun(fullName, checkRunId, installationId,
                        "neutral",
                        "주의 권고 (WARN): 보안 주의 사항 검출",
                        "경미한 취약점 또는 설정 주의 사항이 검출되었습니다. PR 코멘트 내용을 검토 후 병합을 결정하세요.");
                gitHubBotService.removeLabel(fullName, prNumber, installationId, "security-risk");
            }
            case PASS -> {
                // 통과(success) 및 security-risk 라벨 제거
                gitHubBotService.updateCheckRun(fullName, checkRunId, installationId,
                        "success",
                        "승인 (PASS): 보안 위협 미검출",
                        "오픈소스 취약점(CVE), 런타임 환경, 설정 오류 및 코드 내 보안 위협이 발견되지 않았습니다.");
                gitHubBotService.removeLabel(fullName, prNumber, installationId, "security-risk");
            }
        }
    }

    private void sendFailureFeedbackComment(String fullName, Integer prNumber, Long installationId, Exception e) {
        try {
            String failureMessage = e.getMessage() != null ? e.getMessage() : "상세 사유 미확인";
            String failureComment = """
                    ### [PR Guard] 보안 검증 파이프라인 안내: 일시적 오류 발생

                    > **안내:** PR 대상 코드 보안 분석 파이프라인 수행 중 일시적인 오류가 발생했습니다.

                    - **오류 사유:** `%s`
                    - **권장 조치:** 일시적인 네트워크 지연 또는 외부 API 응답 오류일 수 있습니다. `@prguard rescan`을 입력하여 재시도하거나 잠시 후 커밋을 다시 푸시해 주세요.
                    """.formatted(failureMessage);

            gitHubBotService.postComment(fullName, prNumber, installationId, failureComment);
            log.info("[Pipeline] PR #{} 에 실패 안내 코멘트 등록 완료", prNumber);
        } catch (Exception commentEx) {
            log.error("[Pipeline] 실패 안내 코멘트 등록 중 추가 오류 발생: {}", commentEx.getMessage());
        }
    }
}
