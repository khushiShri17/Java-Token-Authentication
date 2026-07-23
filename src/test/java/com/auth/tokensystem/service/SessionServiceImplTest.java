package com.auth.tokensystem.service;

import com.auth.tokensystem.config.AppProperties;
import com.auth.tokensystem.dto.response.SessionResponse;
import com.auth.tokensystem.exception.BadRequestException;
import com.auth.tokensystem.exception.ResourceNotFoundException;
import com.auth.tokensystem.model.RefreshToken;
import com.auth.tokensystem.repository.RefreshTokenRepository;
import com.auth.tokensystem.util.IpAddressUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class SessionServiceImplTest {

    @Mock private RefreshTokenRepository refreshTokenRepository;
    @Mock private AppProperties appProperties;
    @Mock private IpAddressUtil ipAddressUtil;

    @InjectMocks
    private SessionServiceImpl sessionService;

    private AppProperties.Security securityConfig;

    @BeforeEach
    void setUp() {
        securityConfig = new AppProperties.Security();
        securityConfig.setMaxDevicesPerUser(2);
    }

    @Nested
    @DisplayName("getDeviceInfo")
    class GetDeviceInfoTests {

        @Mock private HttpServletRequest request;

        @Test
        @DisplayName("should return User-Agent header")
        void returnsUserAgent() {
            when(request.getHeader("User-Agent")).thenReturn("Mozilla/5.0");
            assertThat(sessionService.getDeviceInfo(request)).isEqualTo("Mozilla/5.0");
        }

        @Test
        @DisplayName("should return 'Unknown device' when User-Agent is null")
        void returnsUnknownWhenNull() {
            when(request.getHeader("User-Agent")).thenReturn(null);
            assertThat(sessionService.getDeviceInfo(request)).isEqualTo("Unknown device");
        }

        @Test
        @DisplayName("should return 'Unknown device' when User-Agent is blank")
        void returnsUnknownWhenBlank() {
            when(request.getHeader("User-Agent")).thenReturn("   ");
            assertThat(sessionService.getDeviceInfo(request)).isEqualTo("Unknown device");
        }
    }

    @Nested
    @DisplayName("updateExistingSession")
    class UpdateExistingSessionTests {

        @Test
        @DisplayName("should update existing session and return true")
        void updatesExisting() {
            RefreshToken existing = new RefreshToken();
            existing.setId("rt1");
            existing.setToken("old-token");
            existing.setUser("user1");

            when(refreshTokenRepository.findByUserAndDeviceInfo("user1", "Chrome"))
                    .thenReturn(Optional.of(existing));
            when(refreshTokenRepository.save(any(RefreshToken.class))).thenAnswer(inv -> inv.getArgument(0));

            Instant expiry = Instant.now().plusSeconds(3600);
            boolean result = sessionService.updateExistingSession("user1", "Chrome",
                    "new-token", "10.0.0.1", expiry);

            assertThat(result).isTrue();
            assertThat(existing.getToken()).isEqualTo("new-token");
            assertThat(existing.getIpAddress()).isEqualTo("10.0.0.1");
            assertThat(existing.getExpiresAt()).isEqualTo(expiry);
        }

        @Test
        @DisplayName("should return false when no existing session found")
        void noExistingSession() {
            when(refreshTokenRepository.findByUserAndDeviceInfo("user1", "Safari"))
                    .thenReturn(Optional.empty());

            boolean result = sessionService.updateExistingSession("user1", "Safari",
                    "token", "10.0.0.1", Instant.now());

            assertThat(result).isFalse();
            verify(refreshTokenRepository, never()).save(any());
        }
    }

    @Nested
    @DisplayName("enforceDeviceLimit")
    class EnforceDeviceLimitTests {

        @Test
        @DisplayName("should delete oldest session when at device limit")
        void deletesOldestWhenAtLimit() {
            when(appProperties.getSecurity()).thenReturn(securityConfig);
            when(refreshTokenRepository.countByUser("user1")).thenReturn(2L);

            RefreshToken oldest = new RefreshToken();
            oldest.setId("oldest-id");
            when(refreshTokenRepository.findFirstByUserOrderByLastUsedAsc("user1"))
                    .thenReturn(Optional.of(oldest));

            sessionService.enforceDeviceLimit("user1");

            verify(refreshTokenRepository).deleteById("oldest-id");
        }

        @Test
        @DisplayName("should not delete when under device limit")
        void noDeleteWhenUnderLimit() {
            when(appProperties.getSecurity()).thenReturn(securityConfig);
            when(refreshTokenRepository.countByUser("user1")).thenReturn(1L);

            sessionService.enforceDeviceLimit("user1");

            verify(refreshTokenRepository, never()).deleteById(anyString());
        }
    }

    @Nested
    @DisplayName("getActiveSessions")
    class GetActiveSessionsTests {

        @Test
        @DisplayName("should return sessions with current flag set correctly")
        void returnsSessionsWithCurrentFlag() {
            RefreshToken session1 = new RefreshToken();
            session1.setId("s1");
            session1.setToken("current-token");
            session1.setDeviceInfo("Chrome");
            session1.setIpAddress("10.0.0.1");
            session1.setIssuedAt(Instant.now());
            session1.setLastUsed(Instant.now());

            RefreshToken session2 = new RefreshToken();
            session2.setId("s2");
            session2.setToken("other-token");
            session2.setDeviceInfo("Firefox");
            session2.setIpAddress("10.0.0.2");
            session2.setIssuedAt(Instant.now());
            session2.setLastUsed(Instant.now());

            when(refreshTokenRepository.findByUserOrderByLastUsedDesc("user1"))
                    .thenReturn(List.of(session1, session2));

            List<SessionResponse> sessions = sessionService.getActiveSessions("user1", "current-token");

            assertThat(sessions).hasSize(2);
            assertThat(sessions.get(0).isCurrent()).isTrue();
            assertThat(sessions.get(1).isCurrent()).isFalse();
        }

        @Test
        @DisplayName("should handle null current refresh token")
        void handlesNullCurrentToken() {
            RefreshToken session = new RefreshToken();
            session.setId("s1");
            session.setToken("some-token");
            session.setDeviceInfo("Chrome");
            session.setIpAddress("10.0.0.1");
            session.setIssuedAt(Instant.now());
            session.setLastUsed(Instant.now());

            when(refreshTokenRepository.findByUserOrderByLastUsedDesc("user1"))
                    .thenReturn(List.of(session));

            List<SessionResponse> sessions = sessionService.getActiveSessions("user1", null);

            assertThat(sessions).hasSize(1);
            assertThat(sessions.get(0).isCurrent()).isFalse();
        }
    }

    @Nested
    @DisplayName("logoutAllOtherDevices")
    class LogoutAllOtherDevicesTests {

        @Test
        @DisplayName("should delete all sessions except current and return count")
        void deletesOtherSessions() {
            when(refreshTokenRepository.countByUser("user1")).thenReturn(3L, 1L);

            long deleted = sessionService.logoutAllOtherDevices("user1", "current-token");

            assertThat(deleted).isEqualTo(2);
            verify(refreshTokenRepository).deleteByUserAndTokenNot("user1", "current-token");
        }

        @Test
        @DisplayName("should throw BadRequestException when no refresh token")
        void throwsWhenNoToken() {
            assertThatThrownBy(() -> sessionService.logoutAllOtherDevices("user1", null))
                    .isInstanceOf(BadRequestException.class);
        }

        @Test
        @DisplayName("should throw BadRequestException when blank refresh token")
        void throwsWhenBlankToken() {
            assertThatThrownBy(() -> sessionService.logoutAllOtherDevices("user1", "   "))
                    .isInstanceOf(BadRequestException.class);
        }
    }

    @Nested
    @DisplayName("terminateSession")
    class TerminateSessionTests {

        @Mock private HttpServletRequest request;
        @Mock private HttpServletResponse response;

        @Test
        @DisplayName("should terminate a different session")
        void terminatesOtherSession() {
            RefreshToken session = new RefreshToken();
            session.setId("session-1");
            session.setToken("other-token");
            session.setUser("user1");

            when(refreshTokenRepository.findById("session-1")).thenReturn(Optional.of(session));

            sessionService.terminateSession("session-1", "user1", "current-token", request, response);

            verify(refreshTokenRepository).deleteById("session-1");
        }

        @Test
        @DisplayName("should throw BadRequestException('CURRENT_SESSION') when terminating own session")
        void throwsForCurrentSession() {
            RefreshToken session = new RefreshToken();
            session.setId("session-1");
            session.setToken("current-token");
            session.setUser("user1");

            when(refreshTokenRepository.findById("session-1")).thenReturn(Optional.of(session));

            assertThatThrownBy(() -> sessionService.terminateSession(
                    "session-1", "user1", "current-token", request, response))
                    .isInstanceOf(BadRequestException.class)
                    .hasMessage("CURRENT_SESSION");
        }

        @Test
        @DisplayName("should throw ResourceNotFoundException for non-existent session")
        void throwsForNonExistentSession() {
            when(refreshTokenRepository.findById("bad-id")).thenReturn(Optional.empty());

            assertThatThrownBy(() -> sessionService.terminateSession(
                    "bad-id", "user1", "current-token", request, response))
                    .isInstanceOf(ResourceNotFoundException.class);
        }

        @Test
        @DisplayName("should throw ResourceNotFoundException when session belongs to different user")
        void throwsForWrongUser() {
            RefreshToken session = new RefreshToken();
            session.setId("session-1");
            session.setToken("some-token");
            session.setUser("other-user");

            when(refreshTokenRepository.findById("session-1")).thenReturn(Optional.of(session));

            assertThatThrownBy(() -> sessionService.terminateSession(
                    "session-1", "user1", "current-token", request, response))
                    .isInstanceOf(ResourceNotFoundException.class);
        }
    }
}
