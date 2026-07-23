package com.auth.tokensystem.controller;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.lang.management.ManagementFactory;
import java.time.Instant;
import java.util.Map;

@RestController
public class HealthCheckController {

    @Value("${spring.profiles.active:development}")
    private String environment;

    @GetMapping("/healthcheck")
    public ResponseEntity<Map<String, Object>> healthCheck() {
        long uptimeMs = ManagementFactory.getRuntimeMXBean().getUptime();
        double uptimeSeconds = uptimeMs / 1000.0;

        return ResponseEntity.ok(Map.of(
                "status", "Ok",
                "message", "Server is running",
                "environment", environment,
                "uptime", uptimeSeconds,
                "timestamp", Instant.now().toString()
        ));
    }
}
