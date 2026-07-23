package com.auth.tokensystem.controller;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Map;

import static org.assertj.core.api.Assertions.*;

class HealthCheckControllerTest {

    @Test
    @DisplayName("should return OK status with uptime and timestamp")
    void healthCheck_ReturnsOk() {
        HealthCheckController controller = new HealthCheckController();
        ReflectionTestUtils.setField(controller, "environment", "development");

        ResponseEntity<Map<String, Object>> result = controller.healthCheck();

        assertThat(result.getStatusCode().value()).isEqualTo(200);
        Map<String, Object> body = result.getBody();
        assertThat(body).containsKey("status");
        assertThat(body.get("status")).isEqualTo("Ok");
        assertThat(body).containsKey("message");
        assertThat(body).containsKey("uptime");
        assertThat(body).containsKey("timestamp");
        assertThat(body).containsEntry("environment", "development");
    }
}
