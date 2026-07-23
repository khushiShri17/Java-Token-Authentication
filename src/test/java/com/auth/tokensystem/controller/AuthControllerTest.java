package com.auth.tokensystem.controller;

import com.auth.tokensystem.dto.request.*;
import com.auth.tokensystem.dto.response.ApiResponse;
import com.auth.tokensystem.dto.response.SessionResponse;
import com.auth.tokensystem.dto.response.UserResponse;
import com.auth.tokensystem.exception.BadRequestException;
import com.auth.tokensystem.model.User;
import com.auth.tokensystem.security.JwtTokenProvider;
import com.auth.tokensystem.service.AuthService;
import com.auth.tokensystem.service.SessionService;
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
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthControllerTest {

    @Mock private AuthService authService;
    @Mock private SessionService sessionService;
    @Mock private JwtTokenProvider jwtTokenProvider;

    @InjectMocks
    private AuthController authController;

    private User testUser;

    @BeforeEach
    void setUp() {
        testUser = new User();
        testUser.setId("user1");
        testUser.setName("John");
        testUser.setEmail("john@example.com");
        testUser.setRole(User.Role.USER);
        testUser.setVerified(true);
        testUser.setCreatedAt(Instant.now());
    }

    @Test
    @DisplayName("should return 201 on successful registration")
    void register_Returns201() {
        RegisterRequest request = new RegisterRequest();
        request.setName("John");
        request.setEmail("john@example.com");
        request.setPassword("Password1!");

        UserResponse userResponse = UserResponse.from(testUser);
        when(authService.register(request)).thenReturn(ApiResponse.success("Registered", userResponse));

        ResponseEntity<ApiResponse<UserResponse>> result = authController.register(request);

        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        assertThat(result.getBody().isSuccess()).isTrue();
    }

    @Test
    @DisplayName("should return 200 on successful login")
    void login_Returns200() {
        LoginRequest request = new LoginRequest();
        request.setEmail("john@example.com");
        request.setPassword("Password1!");

        HttpServletRequest httpRequest = mock(HttpServletRequest.class);
        HttpServletResponse httpResponse = mock(HttpServletResponse.class);

        UserResponse userResponse = UserResponse.from(testUser);
        when(authService.login(request, httpRequest, httpResponse))
                .thenReturn(ApiResponse.success("Logged in", userResponse));

        ResponseEntity<ApiResponse<UserResponse>> result =
                authController.login(request, httpRequest, httpResponse);

        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    @DisplayName("should return 200 on email verification")
    void verifyEmail_Returns200() {
        when(authService.verifyEmail("token123")).thenReturn(ApiResponse.success("Verified"));

        ResponseEntity<ApiResponse<Void>> result = authController.verifyEmail("token123");

        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(result.getBody().isSuccess()).isTrue();
    }

    @Test
    @DisplayName("should return profile with authenticated user")
    void getProfile_ReturnsUserData() {
        UserResponse userResponse = UserResponse.from(testUser);
        when(authService.getProfile("user1")).thenReturn(ApiResponse.success("Profile", userResponse));

        ResponseEntity<ApiResponse<UserResponse>> result = authController.getProfile(testUser);

        assertThat(result.getBody().getData().getEmail()).isEqualTo("john@example.com");
    }

    @Nested
    @DisplayName("Sessions")
    class SessionTests {

        @Test
        @DisplayName("should return active sessions list")
        void getActiveSessions() {
            HttpServletRequest request = mock(HttpServletRequest.class);
            when(jwtTokenProvider.extractRefreshTokenFromRequest(request)).thenReturn("current-token");

            SessionResponse session = new SessionResponse();
            session.setId("s1");
            session.setDeviceInfo("Chrome");
            session.setCurrent(true);

            when(sessionService.getActiveSessions("user1", "current-token"))
                    .thenReturn(List.of(session));

            ResponseEntity<ApiResponse<Map<String, List<SessionResponse>>>> result =
                    authController.getActiveSessions(testUser, request);

            assertThat(result.getBody().getData().get("sessions")).hasSize(1);
        }

        @Test
        @DisplayName("should logout all other devices and return count")
        void logoutAllOtherDevices() {
            HttpServletRequest request = mock(HttpServletRequest.class);
            when(jwtTokenProvider.extractRefreshTokenFromRequest(request)).thenReturn("current-token");
            when(sessionService.logoutAllOtherDevices("user1", "current-token")).thenReturn(2L);

            ResponseEntity<ApiResponse<Map<String, Long>>> result =
                    authController.logoutAllOtherDevices(testUser, request);

            assertThat(result.getBody().getData().get("deletedSessions")).isEqualTo(2L);
        }

        @Test
        @DisplayName("should terminate a specific session")
        void terminateSession_OtherDevice() {
            HttpServletRequest request = mock(HttpServletRequest.class);
            HttpServletResponse response = mock(HttpServletResponse.class);
            when(jwtTokenProvider.extractRefreshTokenFromRequest(request)).thenReturn("current-token");

            ResponseEntity<ApiResponse<Void>> result =
                    authController.terminateSession("session-1", testUser, request, response);

            assertThat(result.getBody().getMessage()).contains("terminated successfully");
        }

        @Test
        @DisplayName("should trigger full logout when terminating current session")
        void terminateSession_CurrentDevice_TriggersLogout() {
            HttpServletRequest request = mock(HttpServletRequest.class);
            HttpServletResponse response = mock(HttpServletResponse.class);
            when(jwtTokenProvider.extractRefreshTokenFromRequest(request)).thenReturn("current-token");

            doThrow(new BadRequestException("CURRENT_SESSION")).when(sessionService)
                    .terminateSession("session-1", "user1", "current-token", request, response);
            when(authService.logout(request, response)).thenReturn(ApiResponse.success("Logged out"));

            ResponseEntity<ApiResponse<Void>> result =
                    authController.terminateSession("session-1", testUser, request, response);

            assertThat(result.getBody().getMessage()).contains("Logged out");
            verify(authService).logout(request, response);
        }
    }

    @Test
    @DisplayName("should return admin data for ADMIN role user")
    void adminEndpoint() {
        User admin = new User();
        admin.setId("admin1");
        admin.setName("Admin");
        admin.setEmail("admin@example.com");
        admin.setRole(User.Role.ADMIN);
        admin.setVerified(true);
        admin.setCreatedAt(Instant.now());

        ResponseEntity<ApiResponse<Map<String, UserResponse>>> result =
                authController.adminEndpoint(admin);

        assertThat(result.getBody().isSuccess()).isTrue();
        assertThat(result.getBody().getMessage()).contains("Admin access granted");
        assertThat(result.getBody().getData().get("user").getRole()).isEqualTo("admin");
    }
}
