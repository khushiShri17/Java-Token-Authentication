package com.auth.tokensystem.security;

import com.auth.tokensystem.config.AppProperties;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

class JwtTokenProviderTest {

    private JwtTokenProvider jwtTokenProvider;

    // Secrets must be at least 32 chars for HMAC-SHA256
    private static final String ACCESS_SECRET = "test-access-secret-key-at-least-32-characters-long";
    private static final String REFRESH_SECRET = "test-refresh-secret-key-at-least-32-characters-long";

    @BeforeEach
    void setUp() {
        AppProperties props = new AppProperties();
        props.getJwt().getAccessToken().setSecret(ACCESS_SECRET);
        props.getJwt().getAccessToken().setExpiresIn(Duration.ofMinutes(15));
        props.getJwt().getRefreshToken().setSecret(REFRESH_SECRET);
        props.getJwt().getRefreshToken().setExpiresIn(Duration.ofDays(7));

        jwtTokenProvider = new JwtTokenProvider(props);
    }

    @Nested
    @DisplayName("Token Generation & Validation")
    class TokenGenerationTests {

        @Test
        @DisplayName("should generate a valid access token")
        void generateAccessToken() {
            String token = jwtTokenProvider.generateAccessToken("user123");

            assertThat(token).isNotNull().isNotBlank();
            assertThat(jwtTokenProvider.validateAccessToken(token)).isTrue();
        }

        @Test
        @DisplayName("should extract userId from access token")
        void extractUserId() {
            String token = jwtTokenProvider.generateAccessToken("user456");

            String userId = jwtTokenProvider.getUserIdFromAccessToken(token);

            assertThat(userId).isEqualTo("user456");
        }

        @Test
        @DisplayName("should extract userId from refresh token")
        void extractUserIdFromRefreshToken() {
            String token = jwtTokenProvider.generateRefreshToken("user789");

            String userId = jwtTokenProvider.getUserIdFromRefreshToken(token);

            assertThat(userId).isEqualTo("user789");
        }

        @Test
        @DisplayName("should return false for an invalid access token")
        void invalidToken() {
            assertThat(jwtTokenProvider.validateAccessToken("invalid.token.here")).isFalse();
        }

        @Test
        @DisplayName("should return false for a null token")
        void nullToken() {
            assertThat(jwtTokenProvider.validateAccessToken(null)).isFalse();
        }

        @Test
        @DisplayName("should return false for empty token")
        void emptyToken() {
            assertThat(jwtTokenProvider.validateAccessToken("")).isFalse();
        }

        @Test
        @DisplayName("should not validate access token with refresh secret")
        void accessTokenInvalidWithRefreshSecret() {
            String refreshToken = jwtTokenProvider.generateRefreshToken("user123");

            // A refresh token should not validate as an access token
            assertThat(jwtTokenProvider.validateAccessToken(refreshToken)).isFalse();
        }

        @Test
        @DisplayName("should return expiration date in the future")
        void expirationInFuture() {
            String token = jwtTokenProvider.generateAccessToken("user123");

            Instant expiration = jwtTokenProvider.getAccessTokenExpiration(token);

            assertThat(expiration).isAfter(Instant.now());
        }

        @Test
        @DisplayName("should return correct refresh token expiry duration")
        void refreshTokenExpiry() {
            assertThat(jwtTokenProvider.getRefreshTokenExpiry()).isEqualTo(Duration.ofDays(7));
        }
    }

    @Nested
    @DisplayName("Token Extraction from Request")
    class TokenExtractionTests {

        @Test
        @DisplayName("should extract access token from cookie")
        void extractFromCookie() {
            HttpServletRequest request = mock(HttpServletRequest.class);
            Cookie accessCookie = new Cookie("accessToken", "jwt-from-cookie");
            when(request.getCookies()).thenReturn(new Cookie[]{accessCookie});

            String token = jwtTokenProvider.extractTokenFromRequest(request);

            assertThat(token).isEqualTo("jwt-from-cookie");
        }

        @Test
        @DisplayName("should extract access token from Authorization header")
        void extractFromBearerHeader() {
            HttpServletRequest request = mock(HttpServletRequest.class);
            when(request.getCookies()).thenReturn(null);
            when(request.getHeader("Authorization")).thenReturn("Bearer jwt-from-header");

            String token = jwtTokenProvider.extractTokenFromRequest(request);

            assertThat(token).isEqualTo("jwt-from-header");
        }

        @Test
        @DisplayName("should prioritize cookie over Authorization header")
        void cookiePriorityOverHeader() {
            HttpServletRequest request = mock(HttpServletRequest.class);
            Cookie accessCookie = new Cookie("accessToken", "cookie-token");
            when(request.getCookies()).thenReturn(new Cookie[]{accessCookie});
            // Header should not even be checked

            String token = jwtTokenProvider.extractTokenFromRequest(request);

            assertThat(token).isEqualTo("cookie-token");
            verify(request, never()).getHeader("Authorization");
        }

        @Test
        @DisplayName("should return null when no token present")
        void noTokenPresent() {
            HttpServletRequest request = mock(HttpServletRequest.class);
            when(request.getCookies()).thenReturn(null);
            when(request.getHeader("Authorization")).thenReturn(null);

            String token = jwtTokenProvider.extractTokenFromRequest(request);

            assertThat(token).isNull();
        }

        @Test
        @DisplayName("should return null for non-Bearer Authorization header")
        void nonBearerHeader() {
            HttpServletRequest request = mock(HttpServletRequest.class);
            when(request.getCookies()).thenReturn(null);
            when(request.getHeader("Authorization")).thenReturn("Basic abc123");

            String token = jwtTokenProvider.extractTokenFromRequest(request);

            assertThat(token).isNull();
        }

        @Test
        @DisplayName("should extract refresh token from cookie")
        void extractRefreshToken() {
            HttpServletRequest request = mock(HttpServletRequest.class);
            Cookie refreshCookie = new Cookie("refreshToken", "refresh-jwt");
            when(request.getCookies()).thenReturn(new Cookie[]{refreshCookie});

            String token = jwtTokenProvider.extractRefreshTokenFromRequest(request);

            assertThat(token).isEqualTo("refresh-jwt");
        }

        @Test
        @DisplayName("should return null when no refresh token cookie")
        void noRefreshTokenCookie() {
            HttpServletRequest request = mock(HttpServletRequest.class);
            when(request.getCookies()).thenReturn(null);

            String token = jwtTokenProvider.extractRefreshTokenFromRequest(request);

            assertThat(token).isNull();
        }

        @Test
        @DisplayName("should return null when cookies exist but no refreshToken cookie")
        void wrongCookieName() {
            HttpServletRequest request = mock(HttpServletRequest.class);
            Cookie otherCookie = new Cookie("sessionId", "abc");
            when(request.getCookies()).thenReturn(new Cookie[]{otherCookie});

            String token = jwtTokenProvider.extractRefreshTokenFromRequest(request);

            assertThat(token).isNull();
        }
    }
}
