package com.auth.tokensystem.util;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.*;

class SecureTokenUtilTest {

    private final SecureTokenUtil secureTokenUtil = new SecureTokenUtil();

    @Test
    @DisplayName("should generate a 64-char hex string by default (32 bytes)")
    void defaultTokenLength() {
        String token = secureTokenUtil.generateToken();

        assertThat(token).hasSize(64);
        assertThat(token).matches("^[0-9a-f]+$");
    }

    @Test
    @DisplayName("should generate token with custom byte length")
    void customLength() {
        String token = secureTokenUtil.generateToken(16);

        assertThat(token).hasSize(32); // 16 bytes = 32 hex chars
        assertThat(token).matches("^[0-9a-f]+$");
    }

    @Test
    @DisplayName("should generate unique tokens on each call")
    void uniqueTokens() {
        String token1 = secureTokenUtil.generateToken();
        String token2 = secureTokenUtil.generateToken();

        assertThat(token1).isNotEqualTo(token2);
    }

    @Test
    @DisplayName("should generate only lowercase hex characters")
    void lowercaseHex() {
        String token = secureTokenUtil.generateToken();

        assertThat(token).isEqualTo(token.toLowerCase());
    }
}
