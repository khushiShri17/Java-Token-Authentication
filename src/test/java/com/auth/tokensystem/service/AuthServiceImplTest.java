package com.auth.tokensystem.service;

import com.auth.tokensystem.config.AppProperties;
import com.auth.tokensystem.dto.request.*;
import com.auth.tokensystem.dto.response.ApiResponse;
import com.auth.tokensystem.dto.response.UserResponse;
import com.auth.tokensystem.exception.*;
import com.auth.tokensystem.model.RefreshToken;
import com.auth.tokensystem.model.User;
import com.auth.tokensystem.repository.RefreshTokenRepository;
import com.auth.tokensystem.repository.UserRepository;
import com.auth.tokensystem.security.JwtTokenProvider;
import com.auth.tokensystem.util.CookieUtil;
import com.auth.tokensystem.util.SecureTokenUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceImplTest {

    @Mock private UserRepository userRepository;
    @Mock private RefreshTokenRepository refreshTokenRepository;
    @Mock private PasswordEncoder passwordEncoder;
    @Mock private JwtTokenProvider jwtTokenProvider;
    @Mock private SecureTokenUtil secureTokenUtil;
    @Mock private CookieUtil cookieUtil;
    @Mock private EmailService emailService;
    @Mock private SessionService sessionService;
    @Mock private TokenBlacklistService tokenBlacklistService;
    @Mock private AppProperties appProperties;

    @InjectMocks
    private AuthServiceImpl authService;

    private User testUser;
    private AppProperties.Security securityConfig;
    private AppProperties.Jwt jwtConfig;

    @BeforeEach
    void setUp() {
        testUser = new User();
        testUser.setId("user123");
        testUser.setName("John Doe");
        testUser.setEmail("john@example.com");
        testUser.setPassword("$2a$10$encodedPassword");
        testUser.setVerified(true);
        testUser.setRole(User.Role.USER);
        testUser.setFailedLoginAttempts(0);
        testUser.setCreatedAt(Instant.now());

        securityConfig = new AppProperties.Security();
        securityConfig.setMaxLoginAttempts(5);
        securityConfig.setLockoutDurationMinutes(30);
        securityConfig.setMaxDevicesPerUser(2);

        jwtConfig = new AppProperties.Jwt();
        jwtConfig.getAccessToken().setExpiresIn(Duration.ofMinutes(15));
        jwtConfig.getRefreshToken().setExpiresIn(Duration.ofDays(7));
    }

    // ==================== REGISTER ====================

    @Nested
    @DisplayName("Register")
    class RegisterTests {

        private RegisterRequest registerRequest;

        @BeforeEach
        void setUp() {
            registerRequest = new RegisterRequest();
            registerRequest.setName("John Doe");
            registerRequest.setEmail("john@example.com");
            registerRequest.setPassword("Password1!");
        }

        @Test
        @DisplayName("should register a new user successfully")
        void register_Success() {
            when(userRepository.existsByEmail("john@example.com")).thenReturn(false);
            when(passwordEncoder.encode("Password1!")).thenReturn("$2a$10$encoded");
            when(secureTokenUtil.generateToken()).thenReturn("verification-token-123");
            when(userRepository.save(any(User.class))).thenAnswer(inv -> {
                User u = inv.getArgument(0);
                u.setId("newUserId");
                return u;
            });

            ApiResponse<UserResponse> response = authService.register(registerRequest);

            assertThat(response.isSuccess()).isTrue();
            assertThat(response.getMessage()).contains("registered successfully");
            assertThat(response.getData()).isNotNull();
            assertThat(response.getData().getEmail()).isEqualTo("john@example.com");

            verify(emailService).sendVerificationEmail("john@example.com", "verification-token-123");
        }

        @Test
        @DisplayName("should throw ConflictException when email already exists")
        void register_DuplicateEmail() {
            when(userRepository.existsByEmail("john@example.com")).thenReturn(true);

            assertThatThrownBy(() -> authService.register(registerRequest))
                    .isInstanceOf(ConflictException.class)
                    .hasMessageContaining("already exists");

            verify(userRepository, never()).save(any());
        }

        @Test
        @DisplayName("should lowercase and trim the email")
        void register_NormalizesEmail() {
            registerRequest.setEmail("  JOHN@EXAMPLE.COM  ");
            // existsByEmail is called with lowercased (but not yet trimmed) value
            when(userRepository.existsByEmail(anyString())).thenReturn(false);
            when(passwordEncoder.encode(anyString())).thenReturn("encoded");
            when(secureTokenUtil.generateToken()).thenReturn("token");
            when(userRepository.save(any(User.class))).thenAnswer(inv -> inv.getArgument(0));

            authService.register(registerRequest);

            ArgumentCaptor<User> captor = ArgumentCaptor.forClass(User.class);
            verify(userRepository).save(captor.capture());
            // The saved user email should be lowercased and trimmed
            assertThat(captor.getValue().getEmail()).isEqualTo("john@example.com");
        }

        @Test
        @DisplayName("should trim the name")
        void register_TrimsName() {
            registerRequest.setName("  John Doe  ");
            when(userRepository.existsByEmail(anyString())).thenReturn(false);
            when(passwordEncoder.encode(anyString())).thenReturn("encoded");
            when(secureTokenUtil.generateToken()).thenReturn("token");
            when(userRepository.save(any(User.class))).thenAnswer(inv -> inv.getArgument(0));

            authService.register(registerRequest);

            ArgumentCaptor<User> captor = ArgumentCaptor.forClass(User.class);
            verify(userRepository).save(captor.capture());
            assertThat(captor.getValue().getName()).isEqualTo("John Doe");
        }

        @Test
        @DisplayName("should set verification token with 10-minute expiry")
        void register_SetsVerificationToken() {
            when(userRepository.existsByEmail(anyString())).thenReturn(false);
            when(passwordEncoder.encode(anyString())).thenReturn("encoded");
            when(secureTokenUtil.generateToken()).thenReturn("verify-token");
            when(userRepository.save(any(User.class))).thenAnswer(inv -> inv.getArgument(0));

            Instant before = Instant.now().plus(Duration.ofMinutes(9));
            authService.register(registerRequest);
            Instant after = Instant.now().plus(Duration.ofMinutes(11));

            ArgumentCaptor<User> captor = ArgumentCaptor.forClass(User.class);
            verify(userRepository).save(captor.capture());
            User saved = captor.getValue();
            assertThat(saved.getVerificationToken()).isEqualTo("verify-token");
            assertThat(saved.getVerificationTokenTime()).isAfter(before).isBefore(after);
        }

        @Test
        @DisplayName("Bug #8: should propagate EmailSendException on email failure")
        void register_EmailFailurePropagates() {
            when(userRepository.existsByEmail(anyString())).thenReturn(false);
            when(passwordEncoder.encode(anyString())).thenReturn("encoded");
            when(secureTokenUtil.generateToken()).thenReturn("token");
            when(userRepository.save(any(User.class))).thenAnswer(inv -> inv.getArgument(0));
            doThrow(new EmailSendException("SMTP error")).when(emailService)
                    .sendVerificationEmail(anyString(), anyString());

            assertThatThrownBy(() -> authService.register(registerRequest))
                    .isInstanceOf(EmailSendException.class);
        }
    }

    // ==================== VERIFY EMAIL ====================

    @Nested
    @DisplayName("Verify Email")
    class VerifyEmailTests {

        @Test
        @DisplayName("should verify email with valid token")
        void verifyEmail_Success() {
            testUser.setVerified(false);
            testUser.setVerificationToken("valid-token");
            testUser.setVerificationTokenTime(Instant.now().plus(Duration.ofMinutes(5)));

            when(userRepository.findByVerificationToken("valid-token"))
                    .thenReturn(Optional.of(testUser));
            when(userRepository.save(any(User.class))).thenAnswer(inv -> inv.getArgument(0));

            ApiResponse<Void> response = authService.verifyEmail("valid-token");

            assertThat(response.isSuccess()).isTrue();
            assertThat(response.getMessage()).contains("verified successfully");
            assertThat(testUser.isVerified()).isTrue();
            assertThat(testUser.getVerificationToken()).isNull();
            assertThat(testUser.getVerificationTokenTime()).isNull();
        }

        @Test
        @DisplayName("should throw BadRequestException for invalid token")
        void verifyEmail_InvalidToken() {
            when(userRepository.findByVerificationToken("bad-token")).thenReturn(Optional.empty());

            assertThatThrownBy(() -> authService.verifyEmail("bad-token"))
                    .isInstanceOf(BadRequestException.class)
                    .hasMessageContaining("Invalid verification token");
        }

        @Test
        @DisplayName("should throw BadRequestException for expired token")
        void verifyEmail_ExpiredToken() {
            testUser.setVerificationToken("expired-token");
            testUser.setVerificationTokenTime(Instant.now().minus(Duration.ofMinutes(1)));

            when(userRepository.findByVerificationToken("expired-token"))
                    .thenReturn(Optional.of(testUser));

            assertThatThrownBy(() -> authService.verifyEmail("expired-token"))
                    .isInstanceOf(BadRequestException.class)
                    .hasMessageContaining("expired");
        }

        @Test
        @DisplayName("should throw BadRequestException for null token")
        void verifyEmail_NullToken() {
            assertThatThrownBy(() -> authService.verifyEmail(null))
                    .isInstanceOf(BadRequestException.class);
        }

        @Test
        @DisplayName("should throw BadRequestException for blank token")
        void verifyEmail_BlankToken() {
            assertThatThrownBy(() -> authService.verifyEmail("   "))
                    .isInstanceOf(BadRequestException.class);
        }
    }

    // ==================== LOGIN ====================

    @Nested
    @DisplayName("Login")
    class LoginTests {

        private LoginRequest loginRequest;
        @Mock private HttpServletRequest httpRequest;
        @Mock private HttpServletResponse httpResponse;

        @BeforeEach
        void setUp() {
            loginRequest = new LoginRequest();
            loginRequest.setEmail("john@example.com");
            loginRequest.setPassword("Password1!");
        }

        @Test
        @DisplayName("should login successfully with correct credentials")
        void login_Success() {
            when(userRepository.findByEmail("john@example.com")).thenReturn(Optional.of(testUser));
            when(passwordEncoder.matches("Password1!", testUser.getPassword())).thenReturn(true);
            when(jwtTokenProvider.generateAccessToken("user123")).thenReturn("access-jwt");
            when(jwtTokenProvider.generateRefreshToken("user123")).thenReturn("refresh-jwt");
            when(sessionService.getDeviceInfo(httpRequest)).thenReturn("TestBrowser");
            when(sessionService.getClientIp(httpRequest)).thenReturn("127.0.0.1");
            when(appProperties.getJwt()).thenReturn(jwtConfig);
            when(sessionService.updateExistingSession(anyString(), anyString(), anyString(),
                    anyString(), any(Instant.class))).thenReturn(true);

            ApiResponse<UserResponse> response = authService.login(loginRequest, httpRequest, httpResponse);

            assertThat(response.isSuccess()).isTrue();
            assertThat(response.getMessage()).contains("logged in successfully");
            assertThat(response.getData().getEmail()).isEqualTo("john@example.com");
            verify(cookieUtil).setAccessTokenCookie(httpResponse, "access-jwt");
            verify(cookieUtil).setRefreshTokenCookie(eq(httpResponse), eq("refresh-jwt"), anyLong());
        }

        @Test
        @DisplayName("should throw UnauthorizedException for non-existent user")
        void login_UserNotFound() {
            when(userRepository.findByEmail("john@example.com")).thenReturn(Optional.empty());

            assertThatThrownBy(() -> authService.login(loginRequest, httpRequest, httpResponse))
                    .isInstanceOf(UnauthorizedException.class)
                    .hasMessageContaining("Invalid credentials");
        }

        @Test
        @DisplayName("should throw UnauthorizedException for wrong password")
        void login_WrongPassword() {
            when(userRepository.findByEmail("john@example.com")).thenReturn(Optional.of(testUser));
            when(passwordEncoder.matches("Password1!", testUser.getPassword())).thenReturn(false);
            when(appProperties.getSecurity()).thenReturn(securityConfig);

            assertThatThrownBy(() -> authService.login(loginRequest, httpRequest, httpResponse))
                    .isInstanceOf(UnauthorizedException.class)
                    .hasMessageContaining("Invalid credentials");

            verify(userRepository).save(testUser);
            assertThat(testUser.getFailedLoginAttempts()).isEqualTo(1);
        }

        @Test
        @DisplayName("should throw UnauthorizedException for unverified user")
        void login_Unverified() {
            testUser.setVerified(false);
            when(userRepository.findByEmail("john@example.com")).thenReturn(Optional.of(testUser));
            when(passwordEncoder.matches("Password1!", testUser.getPassword())).thenReturn(true);

            assertThatThrownBy(() -> authService.login(loginRequest, httpRequest, httpResponse))
                    .isInstanceOf(UnauthorizedException.class)
                    .hasMessageContaining("verify your email");
        }

        @Test
        @DisplayName("Bug #11: should lock account after max failed attempts")
        void login_AccountLockout() {
            testUser.setFailedLoginAttempts(4); // One more will reach 5 (max)
            when(userRepository.findByEmail("john@example.com")).thenReturn(Optional.of(testUser));
            when(passwordEncoder.matches("Password1!", testUser.getPassword())).thenReturn(false);
            when(appProperties.getSecurity()).thenReturn(securityConfig);

            assertThatThrownBy(() -> authService.login(loginRequest, httpRequest, httpResponse))
                    .isInstanceOf(UnauthorizedException.class);

            assertThat(testUser.getFailedLoginAttempts()).isEqualTo(5);
            assertThat(testUser.getLockoutUntil()).isNotNull();
            assertThat(testUser.getLockoutUntil()).isAfter(Instant.now());
        }

        @Test
        @DisplayName("Bug #11: should reject login when account is locked")
        void login_AccountIsLocked() {
            testUser.setLockoutUntil(Instant.now().plus(Duration.ofMinutes(15)));
            when(userRepository.findByEmail("john@example.com")).thenReturn(Optional.of(testUser));

            assertThatThrownBy(() -> authService.login(loginRequest, httpRequest, httpResponse))
                    .isInstanceOf(AccountLockedException.class)
                    .hasMessageContaining("temporarily locked");
        }

        @Test
        @DisplayName("Bug #11: should allow login after lockout expires")
        void login_LockoutExpired() {
            testUser.setLockoutUntil(Instant.now().minus(Duration.ofMinutes(1)));
            testUser.setFailedLoginAttempts(5);
            when(userRepository.findByEmail("john@example.com")).thenReturn(Optional.of(testUser));
            when(passwordEncoder.matches("Password1!", testUser.getPassword())).thenReturn(true);
            when(jwtTokenProvider.generateAccessToken("user123")).thenReturn("access-jwt");
            when(jwtTokenProvider.generateRefreshToken("user123")).thenReturn("refresh-jwt");
            when(sessionService.getDeviceInfo(httpRequest)).thenReturn("Browser");
            when(sessionService.getClientIp(httpRequest)).thenReturn("127.0.0.1");
            when(appProperties.getJwt()).thenReturn(jwtConfig);
            when(sessionService.updateExistingSession(anyString(), anyString(), anyString(),
                    anyString(), any(Instant.class))).thenReturn(true);

            ApiResponse<UserResponse> response = authService.login(loginRequest, httpRequest, httpResponse);

            assertThat(response.isSuccess()).isTrue();
            assertThat(testUser.getFailedLoginAttempts()).isEqualTo(0);
            assertThat(testUser.getLockoutUntil()).isNull();
        }

        @Test
        @DisplayName("should reset failed attempts on successful login")
        void login_ResetsFailedAttempts() {
            testUser.setFailedLoginAttempts(3);
            when(userRepository.findByEmail("john@example.com")).thenReturn(Optional.of(testUser));
            when(passwordEncoder.matches("Password1!", testUser.getPassword())).thenReturn(true);
            when(jwtTokenProvider.generateAccessToken("user123")).thenReturn("access-jwt");
            when(jwtTokenProvider.generateRefreshToken("user123")).thenReturn("refresh-jwt");
            when(sessionService.getDeviceInfo(httpRequest)).thenReturn("Browser");
            when(sessionService.getClientIp(httpRequest)).thenReturn("127.0.0.1");
            when(appProperties.getJwt()).thenReturn(jwtConfig);
            when(sessionService.updateExistingSession(anyString(), anyString(), anyString(),
                    anyString(), any(Instant.class))).thenReturn(true);

            authService.login(loginRequest, httpRequest, httpResponse);

            assertThat(testUser.getFailedLoginAttempts()).isEqualTo(0);
            assertThat(testUser.getLockoutUntil()).isNull();
        }

        @Test
        @DisplayName("should create new session when no existing session for device")
        void login_CreatesNewSession() {
            when(userRepository.findByEmail("john@example.com")).thenReturn(Optional.of(testUser));
            when(passwordEncoder.matches("Password1!", testUser.getPassword())).thenReturn(true);
            when(jwtTokenProvider.generateAccessToken("user123")).thenReturn("access-jwt");
            when(jwtTokenProvider.generateRefreshToken("user123")).thenReturn("refresh-jwt");
            when(sessionService.getDeviceInfo(httpRequest)).thenReturn("NewDevice");
            when(sessionService.getClientIp(httpRequest)).thenReturn("10.0.0.1");
            when(appProperties.getJwt()).thenReturn(jwtConfig);
            when(sessionService.updateExistingSession(anyString(), anyString(), anyString(),
                    anyString(), any(Instant.class))).thenReturn(false);

            authService.login(loginRequest, httpRequest, httpResponse);

            verify(sessionService).enforceDeviceLimit("user123");
            verify(refreshTokenRepository).save(any(RefreshToken.class));
        }
    }

    // ==================== REFRESH TOKEN ====================

    @Nested
    @DisplayName("Refresh Token")
    class RefreshTokenTests {

        @Mock private HttpServletRequest request;
        @Mock private HttpServletResponse response;

        @Test
        @DisplayName("should refresh tokens successfully")
        void refreshToken_Success() {
            RefreshToken storedToken = new RefreshToken();
            storedToken.setId("rt1");
            storedToken.setToken("old-refresh-token");
            storedToken.setUser("user123");
            storedToken.setExpiresAt(Instant.now().plus(Duration.ofDays(1)));

            when(jwtTokenProvider.extractRefreshTokenFromRequest(request)).thenReturn("old-refresh-token");
            when(refreshTokenRepository.findByToken("old-refresh-token")).thenReturn(Optional.of(storedToken));
            when(userRepository.findById("user123")).thenReturn(Optional.of(testUser));
            when(jwtTokenProvider.generateRefreshToken("user123")).thenReturn("new-refresh-token");
            when(jwtTokenProvider.generateAccessToken("user123")).thenReturn("new-access-token");
            when(appProperties.getJwt()).thenReturn(jwtConfig);
            when(sessionService.getClientIp(request)).thenReturn("127.0.0.1");

            ApiResponse<Void> result = authService.refreshToken(request, response);

            assertThat(result.isSuccess()).isTrue();
            assertThat(storedToken.getToken()).isEqualTo("new-refresh-token");
            verify(cookieUtil).setAccessTokenCookie(response, "new-access-token");
            verify(cookieUtil).setRefreshTokenCookie(eq(response), eq("new-refresh-token"), anyLong());
        }

        @Test
        @DisplayName("should throw UnauthorizedException when no refresh token cookie")
        void refreshToken_NoCookie() {
            when(jwtTokenProvider.extractRefreshTokenFromRequest(request)).thenReturn(null);

            assertThatThrownBy(() -> authService.refreshToken(request, response))
                    .isInstanceOf(UnauthorizedException.class)
                    .hasMessageContaining("No refresh token found");
        }

        @Test
        @DisplayName("should throw UnauthorizedException for invalid refresh token")
        void refreshToken_InvalidToken() {
            when(jwtTokenProvider.extractRefreshTokenFromRequest(request)).thenReturn("bad-token");
            when(refreshTokenRepository.findByToken("bad-token")).thenReturn(Optional.empty());

            assertThatThrownBy(() -> authService.refreshToken(request, response))
                    .isInstanceOf(UnauthorizedException.class)
                    .hasMessageContaining("Invalid refresh token");
        }

        @Test
        @DisplayName("should throw UnauthorizedException for expired refresh token")
        void refreshToken_ExpiredToken() {
            RefreshToken expired = new RefreshToken();
            expired.setId("rt2");
            expired.setToken("expired-token");
            expired.setUser("user123");
            expired.setExpiresAt(Instant.now().minus(Duration.ofHours(1)));

            when(jwtTokenProvider.extractRefreshTokenFromRequest(request)).thenReturn("expired-token");
            when(refreshTokenRepository.findByToken("expired-token")).thenReturn(Optional.of(expired));

            assertThatThrownBy(() -> authService.refreshToken(request, response))
                    .isInstanceOf(UnauthorizedException.class)
                    .hasMessageContaining("expired");

            verify(refreshTokenRepository).deleteById("rt2");
        }
    }

    // ==================== GET PROFILE ====================

    @Nested
    @DisplayName("Get Profile")
    class GetProfileTests {

        @Test
        @DisplayName("should return user profile")
        void getProfile_Success() {
            when(userRepository.findById("user123")).thenReturn(Optional.of(testUser));

            ApiResponse<UserResponse> response = authService.getProfile("user123");

            assertThat(response.isSuccess()).isTrue();
            assertThat(response.getData().getId()).isEqualTo("user123");
            assertThat(response.getData().getName()).isEqualTo("John Doe");
        }

        @Test
        @DisplayName("should throw ResourceNotFoundException for non-existent user")
        void getProfile_NotFound() {
            when(userRepository.findById("nonexistent")).thenReturn(Optional.empty());

            assertThatThrownBy(() -> authService.getProfile("nonexistent"))
                    .isInstanceOf(ResourceNotFoundException.class);
        }
    }

    // ==================== FORGOT PASSWORD ====================

    @Nested
    @DisplayName("Forgot Password")
    class ForgotPasswordTests {

        @Test
        @DisplayName("Bug #4: should return generic response when user exists")
        void forgotPassword_UserExists() {
            ForgotPasswordRequest request = new ForgotPasswordRequest();
            request.setEmail("john@example.com");

            when(userRepository.findByEmail("john@example.com")).thenReturn(Optional.of(testUser));
            when(secureTokenUtil.generateToken()).thenReturn("reset-token");

            ApiResponse<Void> response = authService.forgotPassword(request);

            assertThat(response.isSuccess()).isTrue();
            assertThat(response.getMessage()).contains("If an account with that email exists");
            verify(emailService).sendPasswordResetEmail("john@example.com", "reset-token");
        }

        @Test
        @DisplayName("Bug #4: should return same generic response when user does not exist")
        void forgotPassword_UserDoesNotExist() {
            ForgotPasswordRequest request = new ForgotPasswordRequest();
            request.setEmail("nobody@example.com");

            when(userRepository.findByEmail("nobody@example.com")).thenReturn(Optional.empty());

            ApiResponse<Void> response = authService.forgotPassword(request);

            assertThat(response.isSuccess()).isTrue();
            assertThat(response.getMessage()).contains("If an account with that email exists");
            verify(emailService, never()).sendPasswordResetEmail(anyString(), anyString());
        }

        @Test
        @DisplayName("Bug #4: should not leak user existence on email failure")
        void forgotPassword_EmailFailureStillGenericResponse() {
            ForgotPasswordRequest request = new ForgotPasswordRequest();
            request.setEmail("john@example.com");

            when(userRepository.findByEmail("john@example.com")).thenReturn(Optional.of(testUser));
            when(secureTokenUtil.generateToken()).thenReturn("reset-token");
            doThrow(new EmailSendException("SMTP down")).when(emailService)
                    .sendPasswordResetEmail(anyString(), anyString());

            ApiResponse<Void> response = authService.forgotPassword(request);

            assertThat(response.isSuccess()).isTrue();
            assertThat(response.getMessage()).contains("If an account with that email exists");
        }
    }

    // ==================== RESET PASSWORD ====================

    @Nested
    @DisplayName("Reset Password")
    class ResetPasswordTests {

        @Test
        @DisplayName("should reset password with valid token")
        void resetPassword_Success() {
            ResetPasswordRequest request = new ResetPasswordRequest();
            request.setPassword("NewPass1!");

            when(userRepository.findByPasswordResetTokenAndPasswordResetTokenTimeAfter(
                    eq("valid-token"), any(Instant.class))).thenReturn(Optional.of(testUser));
            when(passwordEncoder.encode("NewPass1!")).thenReturn("$2a$10$newEncoded");

            ApiResponse<Void> response = authService.resetPassword("valid-token", request);

            assertThat(response.isSuccess()).isTrue();
            assertThat(testUser.getPassword()).isEqualTo("$2a$10$newEncoded");
            assertThat(testUser.getPasswordResetToken()).isNull();
            assertThat(testUser.getPasswordResetTokenTime()).isNull();
        }

        @Test
        @DisplayName("should throw BadRequestException for invalid/expired reset token")
        void resetPassword_InvalidToken() {
            ResetPasswordRequest request = new ResetPasswordRequest();
            request.setPassword("NewPass1!");

            when(userRepository.findByPasswordResetTokenAndPasswordResetTokenTimeAfter(
                    eq("bad-token"), any(Instant.class))).thenReturn(Optional.empty());

            assertThatThrownBy(() -> authService.resetPassword("bad-token", request))
                    .isInstanceOf(BadRequestException.class)
                    .hasMessageContaining("Invalid or expired");
        }

        @Test
        @DisplayName("should throw BadRequestException for null token")
        void resetPassword_NullToken() {
            ResetPasswordRequest request = new ResetPasswordRequest();
            request.setPassword("NewPass1!");

            assertThatThrownBy(() -> authService.resetPassword(null, request))
                    .isInstanceOf(BadRequestException.class);
        }
    }

    // ==================== LOGOUT ====================

    @Nested
    @DisplayName("Logout")
    class LogoutTests {

        @Mock private HttpServletRequest request;
        @Mock private HttpServletResponse response;

        @Test
        @DisplayName("should logout and clear all tokens")
        void logout_Success() {
            when(jwtTokenProvider.extractTokenFromRequest(request)).thenReturn("access-token");
            when(jwtTokenProvider.extractRefreshTokenFromRequest(request)).thenReturn("refresh-token");

            ApiResponse<Void> result = authService.logout(request, response);

            assertThat(result.isSuccess()).isTrue();
            verify(refreshTokenRepository).deleteByToken("refresh-token");
            verify(tokenBlacklistService).blacklist("access-token");
            verify(cookieUtil).clearTokenCookies(response);
        }

        @Test
        @DisplayName("should handle logout when no tokens present")
        void logout_NoTokens() {
            when(jwtTokenProvider.extractTokenFromRequest(request)).thenReturn(null);
            when(jwtTokenProvider.extractRefreshTokenFromRequest(request)).thenReturn(null);

            ApiResponse<Void> result = authService.logout(request, response);

            assertThat(result.isSuccess()).isTrue();
            verify(refreshTokenRepository, never()).deleteByToken(anyString());
            verify(tokenBlacklistService, never()).blacklist(anyString());
            verify(cookieUtil).clearTokenCookies(response);
        }
    }
}
