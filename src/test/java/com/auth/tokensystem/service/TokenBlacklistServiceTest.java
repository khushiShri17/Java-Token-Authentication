package com.auth.tokensystem.service;

import com.auth.tokensystem.model.BlacklistedToken;
import com.auth.tokensystem.repository.BlacklistedTokenRepository;
import com.auth.tokensystem.security.JwtTokenProvider;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class TokenBlacklistServiceTest {

    @Mock private BlacklistedTokenRepository blacklistedTokenRepository;
    @Mock private JwtTokenProvider jwtTokenProvider;

    @InjectMocks
    private TokenBlacklistService tokenBlacklistService;

    @Test
    @DisplayName("should blacklist a valid access token")
    void blacklist_ValidToken() {
        Instant expiry = Instant.now().plusSeconds(900);
        when(jwtTokenProvider.getUserIdFromAccessToken("token-abc")).thenReturn("user1");
        when(jwtTokenProvider.getAccessTokenExpiration("token-abc")).thenReturn(expiry);

        tokenBlacklistService.blacklist("token-abc");

        ArgumentCaptor<BlacklistedToken> captor = ArgumentCaptor.forClass(BlacklistedToken.class);
        verify(blacklistedTokenRepository).save(captor.capture());

        BlacklistedToken saved = captor.getValue();
        assertThat(saved.getToken()).isEqualTo("token-abc");
        assertThat(saved.getUser()).isEqualTo("user1");
        assertThat(saved.getExpiresAt()).isEqualTo(expiry);
    }

    @Test
    @DisplayName("should silently handle blacklist failure (e.g., invalid token)")
    void blacklist_InvalidToken_NoException() {
        when(jwtTokenProvider.getUserIdFromAccessToken("bad-token"))
                .thenThrow(new RuntimeException("Parse error"));

        assertThatCode(() -> tokenBlacklistService.blacklist("bad-token"))
                .doesNotThrowAnyException();

        verify(blacklistedTokenRepository, never()).save(any());
    }

    @Test
    @DisplayName("should return true when token is blacklisted")
    void isBlacklisted_True() {
        when(blacklistedTokenRepository.existsByToken("blacklisted-token")).thenReturn(true);

        assertThat(tokenBlacklistService.isBlacklisted("blacklisted-token")).isTrue();
    }

    @Test
    @DisplayName("should return false when token is not blacklisted")
    void isBlacklisted_False() {
        when(blacklistedTokenRepository.existsByToken("valid-token")).thenReturn(false);

        assertThat(tokenBlacklistService.isBlacklisted("valid-token")).isFalse();
    }
}
