package io.github.hanjungho.prguard.controller;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.hanjungho.prguard.service.SecurityScanPipeline;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.util.ReflectionTestUtils;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

class WebhookControllerTest {

    private SecurityScanPipeline pipeline;
    private ObjectMapper objectMapper;
    private WebhookController controller;

    @BeforeEach
    void setUp() {
        pipeline = mock(SecurityScanPipeline.class);
        objectMapper = new ObjectMapper().configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        controller = new WebhookController(pipeline, objectMapper);
    }

    private String calculateHmac(String secret, byte[] data) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        return "sha256=" + HexFormat.of().formatHex(mac.doFinal(data));
    }

    @Test
    @DisplayName("GET /api/ping 호출 시 200 OK와 'pong' 문자열이 반환되어야 한다")
    void shouldReturnPongOnPing() {
        ResponseEntity<String> response = controller.ping();
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals("pong", response.getBody());
    }

    @Test
    @DisplayName("시크릿이 설정된 경우 서명 헤더 누락 시 401 반환")
    void shouldReturn401WhenSignatureHeaderMissing() {
        ReflectionTestUtils.setField(controller, "webhookSecret", "my-secret-token");
        byte[] payload = "{\"action\":\"opened\"}".getBytes(StandardCharsets.UTF_8);

        ResponseEntity<String> response = controller.receiveWebhook(null, payload);

        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
        verify(pipeline, never()).executePipelineAsync(any());
    }

    @Test
    @DisplayName("시크릿이 설정된 경우 위조된 서명이면 401 반환")
    void shouldReturn401WhenSignatureIsInvalid() {
        ReflectionTestUtils.setField(controller, "webhookSecret", "my-secret-token");
        byte[] payload = "{\"action\":\"opened\"}".getBytes(StandardCharsets.UTF_8);

        ResponseEntity<String> response = controller.receiveWebhook("sha256=invalidhexsignature1234567890", payload);

        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
        verify(pipeline, never()).executePipelineAsync(any());
    }

    @Test
    @DisplayName("유효한 HMAC 서명이 전달된 PR opened 이벤트는 202 Accepted 및 비동기 스캔 파이프라인 호출")
    void shouldAcceptAndDispatchWhenValidSignature() throws Exception {
        String secret = "my-secret-token";
        ReflectionTestUtils.setField(controller, "webhookSecret", secret);

        String json = """
                {
                  "action": "opened",
                  "number": 42,
                  "repository": {
                    "full_name": "octocat/Hello-World",
                    "clone_url": "https://github.com/octocat/Hello-World.git"
                  },
                  "pull_request": {
                    "head": {
                      "ref": "feature/security-fix",
                      "sha": "abc1234"
                    }
                  }
                }
                """;
        byte[] payload = json.getBytes(StandardCharsets.UTF_8);
        String signature = calculateHmac(secret, payload);

        ResponseEntity<String> response = controller.receiveWebhook(signature, payload);

        assertEquals(HttpStatus.ACCEPTED, response.getStatusCode());
        verify(pipeline, times(1)).executePipelineAsync(any());
    }

    @Test
    @DisplayName("오픈소스 Fork PR 이벤트인 경우 정상 감지 및 202 Accepted 반환")
    void shouldHandleForkPullRequest() {
        // 시크릿 미설정 시 서명 검증 스킵
        String json = """
                {
                  "action": "opened",
                  "number": 10,
                  "repository": {
                    "full_name": "upstream/repo",
                    "clone_url": "https://github.com/upstream/repo.git"
                  },
                  "pull_request": {
                    "head": {
                      "ref": "contributor-branch",
                      "sha": "forksha123",
                      "repo": {
                        "full_name": "forker/repo",
                        "clone_url": "https://github.com/forker/repo.git"
                      }
                    }
                  }
                }
                """;
        byte[] payload = json.getBytes(StandardCharsets.UTF_8);

        ResponseEntity<String> response = controller.receiveWebhook(null, payload);

        assertEquals(HttpStatus.ACCEPTED, response.getStatusCode());
        verify(pipeline, times(1)).executePipelineAsync(any());
    }

    @Test
    @DisplayName("PR 댓글에 /rescan 명령어 입력 시 202 Accepted 및 executeRescanAsync 호출")
    void shouldTriggerRescanOnChatOpsComment() {
        String json = """
                {
                  "action": "created",
                  "issue": {
                    "number": 15,
                    "pull_request": {}
                  },
                  "comment": {
                    "id": 999,
                    "body": "@prguard /rescan",
                    "user": {
                      "login": "developer",
                      "type": "User"
                    }
                  },
                  "repository": {
                    "full_name": "octocat/Hello-World",
                    "clone_url": "https://github.com/octocat/Hello-World.git"
                  }
                }
                """;
        byte[] payload = json.getBytes(StandardCharsets.UTF_8);

        ResponseEntity<String> response = controller.receiveWebhook(null, payload);

        assertEquals(HttpStatus.ACCEPTED, response.getStatusCode());
        verify(pipeline, times(1)).executeRescanAsync(any());
    }

    @Test
    @DisplayName("PR 댓글이 봇 자신의 댓글인 경우 무한루프 방지를 위해 스킵하고 200 OK 반환")
    void shouldIgnoreBotComment() {
        String json = """
                {
                  "action": "created",
                  "issue": {
                    "number": 15,
                    "pull_request": {}
                  },
                  "comment": {
                    "id": 999,
                    "body": "## PR Guard 리포트",
                    "user": {
                      "login": "pr-guard[bot]",
                      "type": "Bot"
                    }
                  }
                }
                """;
        byte[] payload = json.getBytes(StandardCharsets.UTF_8);

        ResponseEntity<String> response = controller.receiveWebhook(null, payload);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals("Ignored bot comment", response.getBody());
        verify(pipeline, never()).executeRescanAsync(any());
    }

    @Test
    @DisplayName("스캔 대상이 아닌 이벤트(closed 등)는 스킵하고 200 OK 반환")
    void shouldIgnoreNonTargetAction() {
        String json = """
                {
                  "action": "closed",
                  "number": 15,
                  "repository": {
                    "full_name": "octocat/Hello-World"
                  }
                }
                """;
        byte[] payload = json.getBytes(StandardCharsets.UTF_8);

        ResponseEntity<String> response = controller.receiveWebhook(null, payload);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        verify(pipeline, never()).executePipelineAsync(any());
    }
}
