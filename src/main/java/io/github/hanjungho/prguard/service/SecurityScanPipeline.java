package io.github.hanjungho.prguard.service;

import io.github.hanjungho.prguard.dto.GithubWebhookPayload;
import io.github.hanjungho.prguard.dto.PrguardConfig;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
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

    @org.springframework.beans.factory.annotation.Value("${pipeline.dedup-window-minutes:10}")
    private int dedupWindowMinutes = 10;

    @org.springframework.beans.factory.annotation.Value("${pipeline.max-inline-comments:5}")
    private int maxInlineComments = 5;

    @org.springframework.beans.factory.annotation.Value("${github.security-label:security-risk}")
    private String securityLabel = "security-risk";

    @org.springframework.beans.factory.annotation.Value("${github.bot.name:prguard}")
    private String botName = "prguard";

    private long getDedupWindowMs() {
        return Math.max(1, dedupWindowMinutes) * 60 * 1000L;
    }

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
     * GitHub UI에서 개발자가 'Re-run' 또는 'Re-run failed checks' 버튼을 클릭했을 때 비동기 재스캔 실행
     */
    @Async("scanTaskExecutor")
    public void executeRescanForPr(String fullName, Integer prNumber, Long installationId) {
        log.info("[Pipeline] GitHub Checks UI Re-run 요청 수신 (PR #{}, Repo: {})", prNumber, fullName);
        try {
            GitHubBotService.PullRequestDetails prDetails = gitHubBotService.getPullRequestDetails(fullName, prNumber, installationId);
            runScanPipeline(fullName, prNumber, prDetails.cloneUrl(), prDetails.branch(), prDetails.headSha(), installationId);
        } catch (Exception e) {
            log.error("[Pipeline] Re-run 재스캔 준비 실패 (PR #{}, Repo: {}): {}", prNumber, fullName, e.getMessage(), e);
            sendFailureFeedbackComment(fullName, prNumber, installationId, e);
        }
    }

    private record PipelineTarget(
            String fullName,
            Integer prNumber,
            String cloneUrl,
            String branch,
            String headSha,
            Long installationId
    ) {
        String prKey() {
            return fullName + "#" + prNumber;
        }

        String commitKey() {
            return (headSha != null && !headSha.isBlank()) ? prKey() + "@" + headSha : null;
        }
    }

    /**
     * 전체 보안 분석, AI 평가, GitHub Checks 및 레이블 관리 파이프라인
     */
    private void runScanPipeline(String fullName, Integer prNumber, String cloneUrl, String branch, String headSha, Long installationId) {
        PipelineTarget target = resolvePipelineTarget(fullName, prNumber, cloneUrl, branch, headSha, installationId);

        if (isDuplicateOrActive(target)) {
            return;
        }

        Long checkRunId = null;
        try {
            checkRunId = gitHubBotService.createCheckRun(target.fullName(), target.headSha(), target.installationId());
            executePipelineStages(target, checkRunId);
        } catch (Exception e) {
            handlePipelineFailure(target, checkRunId, e);
        } finally {
            finishPipeline(target);
        }
    }

    private PipelineTarget resolvePipelineTarget(String fullName, Integer prNumber, String cloneUrl, String branch, String headSha, Long installationId) {
        String resolvedSha = headSha;
        String resolvedCloneUrl = cloneUrl;
        String resolvedBranch = branch;

        if (resolvedSha == null || resolvedSha.isBlank()) {
            try {
                GitHubBotService.PullRequestDetails details = gitHubBotService.getPullRequestDetails(fullName, prNumber, installationId);
                resolvedSha = details.headSha();
                if (resolvedCloneUrl == null) resolvedCloneUrl = details.cloneUrl();
                if (resolvedBranch == null) resolvedBranch = details.branch();
            } catch (Exception ignored) {}
        }

        return new PipelineTarget(fullName, prNumber, resolvedCloneUrl, resolvedBranch, resolvedSha, installationId);
    }

    private boolean isDuplicateOrActive(PipelineTarget target) {
        String commitKey = target.commitKey();
        if (commitKey != null) {
            Long lastCompletedTime = recentCompletedScans.get(commitKey);
            if (lastCompletedTime != null && (System.currentTimeMillis() - lastCompletedTime) < getDedupWindowMs()) {
                log.info("[Pipeline] ⏭️ 동일 커밋(SHA: {})에 대한 스캔이 최근 이미 완료되었습니다. 중복 스캔 생략 (Repo: {}, PR #{})",
                        target.headSha(), target.fullName(), target.prNumber());
                return true;
            }
        }

        String runningSha = activeScans.putIfAbsent(target.prKey(), target.headSha() != null ? target.headSha() : "UNKNOWN");
        if (runningSha != null) {
            log.warn("[Pipeline] ⚠️ PR #{} 에 대한 스캔이 이미 진행 중입니다 (진행 중 SHA: {}, 신규 요청 SHA: {}). 중복 파이프라인 방지.",
                    target.prNumber(), runningSha, target.headSha());
            return true;
        }

        return false;
    }

    private void executePipelineStages(PipelineTarget target, Long checkRunId) {
        String accessToken = gitHubBotService.getInstallationAccessToken(target.fullName(), target.installationId());

        log.info("[Pipeline] Step 1: PR #{} 코드 Diff 수집 및 Trivy 스캔 비동기 병렬 시작", target.prNumber());
        java.util.concurrent.CompletableFuture<String> prDiffFuture = java.util.concurrent.CompletableFuture.supplyAsync(
                () -> gitHubBotService.getPullRequestDiff(target.fullName(), target.prNumber(), target.installationId())
        );

        log.info("[Pipeline] Step 2: Trivy 종합 보안 스캔 및 커스텀 정책 로드 실행");
        TrivyScannerService.ScanResult scanResult = trivyScannerService.scanRepositoryWithContext(
                target.cloneUrl(), target.branch(), accessToken);

        String prDiff = prDiffFuture.join();

        log.info("[Pipeline] Step 3: Gemini AI 종합 보안 분석 진행 중... (매니페스트 추출 패키지: {}개, 환경: {})",
                scanResult.manifestPackages() != null ? scanResult.manifestPackages().size() : 0,
                scanResult.projectEnvironment());
        LLMAnalysisService.AnalysisOutcome outcome = llmAnalysisService.analyzeVulnerabilities(
                scanResult.scanJson(), prDiff, scanResult.runtimeContext(), scanResult.config(),
                scanResult.manifestPackages(), scanResult.projectEnvironment());

        log.info("[Pipeline] Step 4: GitHub PR #{} 에 통합 분석 리포트 코멘트 등록", target.prNumber());
        gitHubBotService.postComment(target.fullName(), target.prNumber(), target.installationId(), outcome.reportMarkdown().trim());

        List<GitHubBotService.CheckRunAnnotation> annotations = processSecurityFindingsAndPostInlineComments(
                target.fullName(), target.prNumber(), target.headSha(), target.installationId(), prDiff, outcome.summaryPayload());

        applySecurityVerdictToGitHub(target.fullName(), target.prNumber(), checkRunId, target.headSha(),
                target.installationId(), outcome.verdict(), annotations);

        log.info("[Pipeline] 비동기 보안 분석 및 통제 파이프라인 완료 (PR #{}, Repo: {}, Verdict: {})",
                target.prNumber(), target.fullName(), outcome.verdict());
    }

    private void handlePipelineFailure(PipelineTarget target, Long checkRunId, Exception e) {
        log.error("[Pipeline] 보안 분석 및 코멘트 파이프라인 수행 실패 (PR #{}, Repo: {}): {}",
                target.prNumber(), target.fullName(), e.getMessage(), e);

        if (checkRunId != null) {
            gitHubBotService.updateCheckRun(target.fullName(), checkRunId, target.installationId(),
                    "action_required",
                    "스캔 실패: 일시적 오류 발생",
                    "보안 분석 파이프라인 실행 중 오류가 발생했습니다: " + e.getMessage());
        }

        if (target.prNumber() != null && !"N/A".equals(target.fullName())) {
            sendFailureFeedbackComment(target.fullName(), target.prNumber(), target.installationId(), e);
        }
    }

    private void finishPipeline(PipelineTarget target) {
        activeScans.remove(target.prKey());
        if (target.commitKey() != null) {
            recentCompletedScans.put(target.commitKey(), System.currentTimeMillis());
        }
        cleanupExpiredCompletedScans();
    }

    private void cleanupExpiredCompletedScans() {
        if (recentCompletedScans.size() > 200) {
            long threshold = System.currentTimeMillis() - getDedupWindowMs();
            recentCompletedScans.entrySet().removeIf(entry -> entry.getValue() < threshold);
        }
    }

    /**
     * 최종 판정(BLOCK / WARN / PASS)에 따라 GitHub Checks API 결과 업데이트 및 security-risk 라벨, Commit Status 관리
     */
    private void applySecurityVerdictToGitHub(String fullName, Integer prNumber, Long checkRunId,
                                              String headSha, Long installationId,
                                              LLMAnalysisService.SecurityVerdict verdict,
                                              List<GitHubBotService.CheckRunAnnotation> annotations) {
        String statusState;
        String statusDesc;
        String riskLabel = (securityLabel != null && !securityLabel.isBlank()) ? securityLabel.trim() : "security-risk";
        switch (verdict) {
            case BLOCK -> {
                statusState = "failure";
                statusDesc = "차단 권고 (BLOCK): 심각한 보안 위험 검출";
                gitHubBotService.updateCheckRun(fullName, checkRunId, installationId,
                        "failure",
                        statusDesc,
                        "고위험 취약점 또는 코드 내 보안 결함이 검출되어 병합(Merge)이 차단되었습니다. PR 코멘트 및 코드 라인별 안내를 확인해 주세요.",
                        annotations);
                gitHubBotService.addLabel(fullName, prNumber, installationId, riskLabel);
                gitHubBotService.submitPullRequestReview(fullName, prNumber, headSha, installationId, "REQUEST_CHANGES",
                        "### 🛡️ PR Guard 차단 권고 (BLOCK)\n심각한 보안 취약점(CRITICAL/HIGH) 또는 시크릿 노출이 검출되었습니다. 머지 전 조치가 필요합니다.");
            }
            case WARN -> {
                statusState = "success";
                statusDesc = "주의 권고 (WARN): 보안 주의 사항 검출";
                gitHubBotService.updateCheckRun(fullName, checkRunId, installationId,
                        "neutral",
                        statusDesc,
                        "경미한 취약점 또는 설정 주의 사항이 검출되었습니다. PR 코멘트 내용을 검토 후 병합을 결정하세요.",
                        annotations);
                gitHubBotService.removeLabel(fullName, prNumber, installationId, riskLabel);
                gitHubBotService.submitPullRequestReview(fullName, prNumber, headSha, installationId, "COMMENT",
                        "### 🛡️ PR Guard 주의 (WARN)\n주의가 필요한 보안 결함이 검출되었습니다. PR 코멘트 내용을 검토 후 병합을 결정하세요.");
            }
            case PASS -> {
                statusState = "success";
                statusDesc = "승인 (PASS): 보안 위협 미검출";
                gitHubBotService.updateCheckRun(fullName, checkRunId, installationId,
                        "success",
                        statusDesc,
                        "오픈소스 취약점(CVE), 런타임 환경, 설정 오류 및 코드 내 보안 위협이 발견되지 않았습니다.",
                        annotations);
                gitHubBotService.removeLabel(fullName, prNumber, installationId, riskLabel);
                gitHubBotService.submitPullRequestReview(fullName, prNumber, headSha, installationId, "APPROVE",
                        "### 🛡️ PR Guard 승인 (PASS)\n오픈소스 취약점(CVE), 런타임 환경, 설정 오류 및 코드 내 보안 위협이 발견되지 않았습니다. 안전하게 병합할 수 있습니다.");
            }
            default -> {
                statusState = "success";
                statusDesc = "보안 검증 완료";
            }
        }

        // 엔터프라이즈 브랜치 보호 규칙 호환을 위한 GitHub Commit Status 동기화
        if (headSha != null && !headSha.isBlank()) {
            gitHubBotService.createCommitStatus(fullName, headSha, installationId, statusState, statusDesc, null);
        }
    }

    /**
     * 보안 결함(시크릿 노출, 설정 오류)을 분석하여 Check Run Annotation 생성 및
     * PR Diff에 포함된 문제 라인에 1-Click 인라인 리뷰 코멘트를 등록합니다.
     */
    private List<GitHubBotService.CheckRunAnnotation> processSecurityFindingsAndPostInlineComments(
            String repoFullName, Integer prNumber, String headSha, Long installationId,
            String prDiff, LLMAnalysisService.ScanSummaryPayload summaryPayload) {
        List<GitHubBotService.CheckRunAnnotation> annotations = new ArrayList<>();
        if (summaryPayload == null) return annotations;

        Map<String, Set<Integer>> diffHunkLines = parseDiffHunkLines(prDiff);
        int inlineCommentsPosted = 0;
        final int maxAllowedComments = Math.max(1, maxInlineComments);

        // 1. 하드코딩된 시크릿 결함 처리
        if (summaryPayload.secrets() != null) {
            for (LLMAnalysisService.SecretDetail secret : summaryPayload.secrets()) {
                if (secret.targetFile() == null || secret.targetFile().isBlank()) continue;
                int line = Math.max(1, secret.startLine());
                String cleanPath = normalizeFilePath(secret.targetFile());
                String title = "Hardcoded Secret: " + secret.title();
                String message = "코드 내에 민감한 시크릿/인증 토큰이 직접 노출되어 있습니다 (규칙: " + secret.ruleId() + "). 환경 변수나 Secret Manager를 사용하세요.";

                annotations.add(new GitHubBotService.CheckRunAnnotation(cleanPath, line, "failure", title, message));

                if (inlineCommentsPosted < maxAllowedComments && isLineInDiff(diffHunkLines, cleanPath, line)) {
                    String commentBody = """
                            ⚠️ **[PR Guard 보안 경고]** 하드코딩된 시크릿/토큰 감지 (`%s`)
                            > **위험도:** `CRITICAL` (규칙 ID: `%s`)
                            > 
                            > 코드 내에 인증 정보나 암호키가 직접 노출되었습니다. GitHub 저장소에 커밋되면 즉시 유출 사고로 이어질 수 있습니다.
                            > `System.getenv()`, `process.env` 등 환경 변수 또는 Secret Manager를 통해 주입받도록 수정해 주세요.
                            """.formatted(secret.title(), secret.ruleId());

                    if (gitHubBotService.postInlineReviewComment(repoFullName, prNumber, headSha, installationId, cleanPath, line, commentBody)) {
                        inlineCommentsPosted++;
                    }
                }
            }
        }

        // 2. 보안 설정 오류(Misconfiguration) 결함 처리
        if (summaryPayload.misconfigurations() != null) {
            for (LLMAnalysisService.MisconfigDetail misconfig : summaryPayload.misconfigurations()) {
                if (misconfig.targetFile() == null || misconfig.targetFile().isBlank()) continue;
                int line = Math.max(1, misconfig.startLine());
                String cleanPath = normalizeFilePath(misconfig.targetFile());
                boolean isHigh = "CRITICAL".equalsIgnoreCase(misconfig.severity()) || "HIGH".equalsIgnoreCase(misconfig.severity());
                String annotationLevel = isHigh ? "failure" : "warning";
                String title = "Misconfiguration: " + misconfig.title();
                String message = misconfig.message() + (misconfig.resolution().isBlank() ? "" : "\n조치 방안: " + misconfig.resolution());

                annotations.add(new GitHubBotService.CheckRunAnnotation(cleanPath, line, annotationLevel, title, message));

                if (inlineCommentsPosted < maxAllowedComments && isLineInDiff(diffHunkLines, cleanPath, line)) {
                    String resolutionGuide = misconfig.resolution().isBlank() ? "안전한 기본 설정으로 변경하세요." : misconfig.resolution();
                    String commentBody = """
                            ⚠️ **[PR Guard 보안 경고]** 보안 설정 결함 감지 (`%s`)
                            > **위험도:** `%s` (ID: `%s`)
                            > **설명:** %s
                            > **권장 조치:** %s
                            """.formatted(misconfig.title(), misconfig.severity(), misconfig.id(), misconfig.message(), resolutionGuide);

                    if (gitHubBotService.postInlineReviewComment(repoFullName, prNumber, headSha, installationId, cleanPath, line, commentBody)) {
                        inlineCommentsPosted++;
                    }
                }
            }
        }

        log.info("[Pipeline] 코드 결함 분석 완료 (생성된 Annotation: {}개, 등록된 인라인 코멘트: {}개)",
                annotations.size(), inlineCommentsPosted);
        return annotations;
    }

    private String normalizeFilePath(String path) {
        if (path == null) return "";
        String p = path.replace('\\', '/').trim();
        if (p.startsWith("./")) p = p.substring(2);
        if (p.startsWith("/")) p = p.substring(1);
        return p;
    }

    private boolean isLineInDiff(Map<String, Set<Integer>> diffHunkLines, String filePath, int line) {
        if (diffHunkLines == null || filePath == null || diffHunkLines.isEmpty()) {
            return false;
        }
        String cleanPath = normalizeFilePath(filePath);

        for (Map.Entry<String, Set<Integer>> entry : diffHunkLines.entrySet()) {
            String diffFile = normalizeFilePath(entry.getKey());
            if (diffFile.equals(cleanPath) || diffFile.endsWith("/" + cleanPath) || cleanPath.endsWith("/" + diffFile)) {
                return entry.getValue().contains(line);
            }
        }
        return false;
    }

    private Map<String, Set<Integer>> parseDiffHunkLines(String diff) {
        Map<String, Set<Integer>> result = new HashMap<>();
        if (diff == null || diff.isBlank()) return result;

        String currentFile = null;
        int currentLine = 0;

        for (String line : diff.lines().toList()) {
            if (line.startsWith("diff --git ")) {
                int bIdx = line.indexOf(" b/");
                if (bIdx != -1) {
                    currentFile = normalizeFilePath(line.substring(bIdx + 3).trim());
                    result.putIfAbsent(currentFile, new HashSet<>());
                } else {
                    currentFile = null;
                }
            } else if (line.startsWith("@@ ") && currentFile != null) {
                int plusIdx = line.indexOf('+');
                if (plusIdx != -1) {
                    int commaIdx = line.indexOf(',', plusIdx);
                    int spaceIdx = line.indexOf(' ', plusIdx);
                    int endIdx = (commaIdx != -1 && commaIdx < spaceIdx) ? commaIdx : spaceIdx;
                    if (endIdx != -1) {
                        try {
                            currentLine = Integer.parseInt(line.substring(plusIdx + 1, endIdx).trim());
                        } catch (NumberFormatException ignored) {}
                    }
                }
            } else if (currentFile != null && currentLine > 0) {
                if (line.startsWith("+")) {
                    result.get(currentFile).add(currentLine);
                    currentLine++;
                } else if (line.startsWith(" ")) {
                    result.get(currentFile).add(currentLine);
                    currentLine++;
                }
            }
        }
        return result;
    }

    private void sendFailureFeedbackComment(String fullName, Integer prNumber, Long installationId, Exception e) {
        try {
            String failureMessage = e.getMessage() != null ? e.getMessage() : "상세 사유 미확인";
            String rescanCmd = "@" + ((botName != null && !botName.isBlank()) ? botName.trim() : "prguard") + " rescan";
            String actionAdvice = "일시적인 네트워크 지연 또는 외부 API 응답 오류일 수 있습니다. `" + rescanCmd + "`을 입력하여 재시도하거나 잠시 후 커밋을 다시 푸시해 주세요.";

            if (failureMessage.contains("Contents: Read") || failureMessage.contains("접근 권한 부족")
                    || failureMessage.contains("terminal prompts disabled") || failureMessage.contains("could not read Username")) {
                actionAdvice = """
                        **비공개(Private) 저장소의 소스코드를 분석하기 위해서는 GitHub App의 저장소 코드 접근 권한이 필요합니다.**
                        1. **GitHub App 권한 설정**: [GitHub App Settings](https://github.com/settings/apps) -> **Permissions & events** -> **Repository permissions** 에서 **`Contents` 권한을 `Access: Read-only` (또는 Read and write)** 로 변경 후 저장합니다.
                        2. **저장소 설치 승인(Update Permissions)**: 권한 변경 후 해당 계정(또는 조직)의 **Settings -> Applications -> Installed GitHub Apps -> PR Guard** 로 이동하여 **`Review permission update request`** (새 권한 승인) 버튼을 눌러 승인해 주세요.
                        3. 승인 후 PR에서 `%s`을 입력하면 정상적으로 분석이 진행됩니다.
                        """.formatted(rescanCmd);
            }

            String failureComment = """
                    ### [PR Guard] 보안 검증 파이프라인 안내: 접근 권한 또는 일시적 오류 확인 필요

                    > **안내:** PR 대상 코드 보안 분석 파이프라인 수행 중 오류가 발생했습니다.

                    - **오류 사유:** `%s`
                    - **권장 조치:**
                    %s
                    """.formatted(failureMessage, actionAdvice);

            gitHubBotService.postComment(fullName, prNumber, installationId, failureComment);
            log.info("[Pipeline] PR #{} 에 실패 안내 코멘트 등록 완료", prNumber);
        } catch (Exception commentEx) {
            log.error("[Pipeline] 실패 안내 코멘트 등록 중 추가 오류 발생: {}", commentEx.getMessage());
        }
    }
}
