package io.github.hanjungho.prguard.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.client.RestTemplate;

import static org.junit.jupiter.api.Assertions.*;

class GitHubBotServiceTest {

    private GitHubBotService gitHubBotService;

    @BeforeEach
    void setUp() {
        gitHubBotService = new GitHubBotService(new ObjectMapper(), new RestTemplate());
        ReflectionTestUtils.setField(gitHubBotService, "appId", "12345");
        ReflectionTestUtils.setField(gitHubBotService, "privateKeyPath", "dummy.pem");
    }

    @Test
    @DisplayName("Diff 다이어트: .md, .css, .svg 등 보안 무관 파일은 제외되고 실제 코드(.java, .yml)만 보존되어야 한다")
    void shouldFilterOutSecurityIrrelevantFilesFromDiff() {
        String rawDiff = """
                diff --git a/README.md b/README.md
                index 123..456 100644
                --- a/README.md
                +++ b/README.md
                @@ -1,3 +1,5 @@
                 # Title
                +## New Section
                diff --git a/assets/logo.svg b/assets/logo.svg
                index abc..def 100644
                --- a/assets/logo.svg
                +++ b/assets/logo.svg
                @@ -1 +1 @@
                -<svg>old</svg>
                +<svg>new</svg>
                diff --git a/src/main/resources/application.yml b/src/main/resources/application.yml
                index 789..012 100644
                --- a/src/main/resources/application.yml
                +++ b/src/main/resources/application.yml
                @@ -1,2 +1,3 @@
                 server:
                   port: 8080
                +  debug: true
                diff --git a/src/main/java/App.java b/src/main/java/App.java
                index 345..678 100644
                --- a/src/main/java/App.java
                +++ b/src/main/java/App.java
                @@ -10,3 +10,4 @@
                 public void run() {
                +    executeCommand();
                 }
                """;

        String filteredDiff = gitHubBotService.filterSecurityRelevantDiff(rawDiff);

        assertNotNull(filteredDiff);
        assertFalse(filteredDiff.contains("README.md"), "README.md 블록은 제거되어야 함");
        assertFalse(filteredDiff.contains("logo.svg"), "logo.svg 블록은 제거되어야 함");
        assertTrue(filteredDiff.contains("application.yml"), "application.yml은 보존되어야 함");
        assertTrue(filteredDiff.contains("App.java"), "App.java는 보존되어야 함");
    }

    @Test
    @DisplayName("문서/에셋 파일만 수정된 경우 Diff 결과가 완전히 비어있어야 한다")
    void shouldReturnEmptyStringWhenOnlyDocOrAssetsModified() {
        String docOnlyDiff = """
                diff --git a/README.md b/README.md
                index 123..456 100644
                --- a/README.md
                +++ b/README.md
                @@ -1 +1 @@
                +# Updated doc
                diff --git a/styles/main.css b/styles/main.css
                index aaa..bbb 100644
                --- a/styles/main.css
                +++ b/styles/main.css
                @@ -1 +1 @@
                +body { color: red; }
                """;

        String filteredDiff = gitHubBotService.filterSecurityRelevantDiff(docOnlyDiff);

        assertEquals("", filteredDiff, "보안 무관 파일만 수정된 경우 빈 문자열 반환");
    }

    @Test
    @DisplayName("findExistingBotCommentId: 마커가 포함된 이전 리포트 코멘트가 있을 경우 ID 반환")
    void shouldFindExistingBotCommentIdWhenMarkerPresent() {
        RestTemplate mockRestTemplate = org.mockito.Mockito.mock(RestTemplate.class);
        GitHubBotService botService = new GitHubBotService(new ObjectMapper(), mockRestTemplate);

        String commentsJson = """
                [
                  {
                    "id": 1001,
                    "body": "LGTM!",
                    "user": { "login": "reviewer", "type": "User" }
                  },
                  {
                    "id": 2002,
                    "body": "<!-- pr-guard-report-marker -->\\n## 🛡️ PR Guard 보안 분석 리포트",
                    "user": { "login": "pr-guard[bot]", "type": "Bot" }
                  }
                ]
                """;

        org.mockito.Mockito.when(mockRestTemplate.exchange(
                org.mockito.ArgumentMatchers.anyString(),
                org.mockito.ArgumentMatchers.eq(org.springframework.http.HttpMethod.GET),
                org.mockito.ArgumentMatchers.any(),
                org.mockito.ArgumentMatchers.eq(String.class)
        )).thenReturn(org.springframework.http.ResponseEntity.ok(commentsJson));

        Long commentId = botService.findExistingBotCommentId("octocat/repo", 1, "test-token");

        assertEquals(2002L, commentId);
    }

    @Test
    @DisplayName("findExistingBotCommentId: 봇 코멘트가 없을 경우 null 반환")
    void shouldReturnNullWhenNoBotCommentFound() {
        RestTemplate mockRestTemplate = org.mockito.Mockito.mock(RestTemplate.class);
        GitHubBotService botService = new GitHubBotService(new ObjectMapper(), mockRestTemplate);

        String commentsJson = """
                [
                  {
                    "id": 1001,
                    "body": "Please review this PR",
                    "user": { "login": "author", "type": "User" }
                  }
                ]
                """;

        org.mockito.Mockito.when(mockRestTemplate.exchange(
                org.mockito.ArgumentMatchers.anyString(),
                org.mockito.ArgumentMatchers.eq(org.springframework.http.HttpMethod.GET),
                org.mockito.ArgumentMatchers.any(),
                org.mockito.ArgumentMatchers.eq(String.class)
        )).thenReturn(org.springframework.http.ResponseEntity.ok(commentsJson));

        Long commentId = botService.findExistingBotCommentId("octocat/repo", 1, "test-token");

        assertNull(commentId);
    }

    @Test
    @DisplayName("postInlineReviewComment: PR 변경 코드 특정 라인에 인라인 리뷰 코멘트 작성 성공 검증")
    void shouldPostInlineReviewCommentSuccessfully() {
        RestTemplate mockRestTemplate = org.mockito.Mockito.mock(RestTemplate.class);
        GitHubBotService botService = org.mockito.Mockito.spy(new GitHubBotService(new ObjectMapper(), mockRestTemplate));
        org.mockito.Mockito.doReturn("dummy-token").when(botService).getInstallationAccessToken(org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any());

        org.mockito.Mockito.when(mockRestTemplate.postForEntity(
                org.mockito.ArgumentMatchers.contains("/pulls/10/comments"),
                org.mockito.ArgumentMatchers.any(),
                org.mockito.ArgumentMatchers.eq(String.class)
        )).thenReturn(org.springframework.http.ResponseEntity.ok("{\"id\": 12345}"));

        boolean result = botService.postInlineReviewComment(
                "octocat/repo", 10, "abc1234", 100L,
                "src/Main.java", 25, "⚠️ 보안 경고: 위험한 API 호출"
        );

        assertTrue(result, "인라인 리뷰 코멘트 작성이 성공해야 함");
    }

    @Test
    @DisplayName("updateCheckRun: Annotation 목록이 포함된 Check Run 업데이트 검증")
    void shouldUpdateCheckRunWithAnnotations() {
        RestTemplate mockRestTemplate = org.mockito.Mockito.mock(RestTemplate.class);
        GitHubBotService botService = org.mockito.Mockito.spy(new GitHubBotService(new ObjectMapper(), mockRestTemplate));
        org.mockito.Mockito.doReturn("dummy-token").when(botService).getInstallationAccessToken(org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any());

        org.mockito.Mockito.when(mockRestTemplate.exchange(
                org.mockito.ArgumentMatchers.contains("/check-runs/999"),
                org.mockito.ArgumentMatchers.eq(org.springframework.http.HttpMethod.PATCH),
                org.mockito.ArgumentMatchers.any(),
                org.mockito.ArgumentMatchers.eq(String.class)
        )).thenReturn(org.springframework.http.ResponseEntity.ok("{}"));

        assertDoesNotThrow(() -> botService.updateCheckRun(
                "octocat/repo", 999L, 100L,
                "failure", "차단 권고 (BLOCK)", "요약 설명",
                java.util.List.of(new GitHubBotService.CheckRunAnnotation("src/Secret.java", 12, "failure", "Secret Expose", "API Key leaked"))
        ));
    }

    @Test
    @DisplayName("submitPullRequestReview: 공식 PR Review (APPROVE/REQUEST_CHANGES) 제출 성공 검증")
    void shouldSubmitPullRequestReviewSuccessfully() {
        RestTemplate mockRestTemplate = org.mockito.Mockito.mock(RestTemplate.class);
        GitHubBotService botService = org.mockito.Mockito.spy(new GitHubBotService(new ObjectMapper(), mockRestTemplate));
        org.mockito.Mockito.doReturn("dummy-token").when(botService).getInstallationAccessToken(org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any());

        org.mockito.Mockito.when(mockRestTemplate.postForEntity(
                org.mockito.ArgumentMatchers.contains("/pulls/10/reviews"),
                org.mockito.ArgumentMatchers.any(),
                org.mockito.ArgumentMatchers.eq(String.class)
        )).thenReturn(org.springframework.http.ResponseEntity.ok("{\"id\": 5555}"));

        assertDoesNotThrow(() -> botService.submitPullRequestReview(
                "octocat/repo", 10, "sha1234", 100L,
                "APPROVE", "보안 검증 통과"
        ));
    }
}

