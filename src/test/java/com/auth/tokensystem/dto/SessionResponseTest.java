package com.auth.tokensystem.dto;

import com.auth.tokensystem.dto.response.SessionResponse;
import com.auth.tokensystem.model.RefreshToken;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.assertj.core.api.Assertions.*;

class SessionResponseTest {

    @Test
    @DisplayName("should map RefreshToken to SessionResponse with isCurrent=true")
    void currentSession() {
        RefreshToken token = new RefreshToken();
        token.setId("rt1");
        token.setToken("my-token");
        token.setDeviceInfo("Chrome/120.0");
        token.setIpAddress("192.168.1.1");
        token.setLastUsed(Instant.now());
        token.setIssuedAt(Instant.now().minusSeconds(3600));

        SessionResponse dto = SessionResponse.from(token, "my-token");

        assertThat(dto.getId()).isEqualTo("rt1");
        assertThat(dto.getDeviceInfo()).isEqualTo("Chrome/120.0");
        assertThat(dto.getIpAddress()).isEqualTo("192.168.1.1");
        assertThat(dto.isCurrent()).isTrue();
    }

    @Test
    @DisplayName("should set isCurrent=false when token does not match")
    void notCurrentSession() {
        RefreshToken token = new RefreshToken();
        token.setId("rt2");
        token.setToken("other-token");
        token.setDeviceInfo("Firefox");
        token.setIpAddress("10.0.0.1");
        token.setLastUsed(Instant.now());
        token.setIssuedAt(Instant.now());

        SessionResponse dto = SessionResponse.from(token, "my-current-token");

        assertThat(dto.isCurrent()).isFalse();
    }
}
