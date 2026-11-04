package io.github.hanjungho.prguard.controller;

import io.github.hanjungho.prguard.service.SecurityScanPipeline;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;

class WebhookControllerTest {

    @Test
    @DisplayName("GET /api/ping 호출 시 200 OK와 'pong' 문자열이 반환되어야 한다")
    void shouldReturnPongOnPing() {
        SecurityScanPipeline pipeline = mock(SecurityScanPipeline.class);
        WebhookController controller = new WebhookController(pipeline);

        ResponseEntity<String> response = controller.ping();

        assertEquals(200, response.getStatusCode().value());
        assertEquals("pong", response.getBody());
    }
}

