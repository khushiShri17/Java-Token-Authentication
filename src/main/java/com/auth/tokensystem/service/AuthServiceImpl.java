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
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthServiceImpl implements AuthService {

    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;
    private final SecureTokenUtil secureTokenUtil;
    private final CookieUtil cookieUtil;
    private final EmailService emailService;
    private final SessionService sessionService;
    private final TokenBlacklistService tokenBlacklistService;
    private final AppProperties appProperties;

    @Override
    public ApiResponse<UserResponse> register(RegisterRequest request) {
        if (userRepository.existsByEmail(request.getEmail().toLowerCase())) {
            throw new ConflictException("User already exists with this email");
        }

        User user = new User();
        user.setName(request.getName().trim());
        user.setEmail(request.getEmail().toLowerCase().trim());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setVerified(false);

        // Generate verification token (10-minute expiry)
        String token = secureTokenUtil.generateToken();
        user.setVerificationToken(token);
        user.setVerificationTokenTime(Instant.now().plus(Duration.ofMinutes(10)));

        user = userRepository.save(user);

        // Bug #8 fix: email failure throws EmailSendException (502 to client)
        emailService.sendVerificationEmail(user.getEmail(), token);

        return ApiResponse.success(
                "User registered successfully. Please check your email to verify your account",
                UserResponse.from(user)
        );
    }

    @Override
    public ApiResponse<Void> verifyEmail(String token) {
        if (token == null || token.isBlank()) {
            throw new BadRequestException("Verification token is required");
        }

        // Bug #5 fix: consistent response shape using ApiResponse
        User user = userRepository.findByVerificationToken(token)
                .orElseThrow(() -> new BadRequestException("Invalid verification token"));

        if (Instant.now().isAfter(user.getVerificationTokenTime())) {
            throw new BadRequestException("Verification token has expired");
        }

        user.setVerified(true);
        user.setVerificationToken(null);
        user.setVerificationTokenTime(null);
        userRepository.save(user);

        return ApiResponse.success("Account verified successfully, you can now login");
    }

    @Override
    public ApiResponse<UserResponse> login(LoginRequest request, HttpServletRequest httpRequest,
                                            HttpServletResponse httpResponse) {
        String email = request.getEmail().toLowerCase().trim();
        User user = userRepository.findByEmail(email).orElse(null);

        if (user == null) {
            throw new UnauthorizedException("Invalid credentials");
        }

        // Bug #11 fix: check account lockout
        if (user.getLockoutUntil() != null && Instant.now().isBefore(user.getLockoutUntil())) {
            throw new AccountLockedException(
                    "Account is temporarily locked due to too many failed login attempts. Please try again later.");
        }

        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            // Increment failed attempts
            int attempts = user.getFailedLoginAttempts() + 1;
            user.setFailedLoginAttempts(attempts);

            if (attempts >= appProperties.getSecurity().getMaxLoginAttempts()) {
                user.setLockoutUntil(Instant.now().plus(
                        Duration.ofMinutes(appProperties.getSecurity().getLockoutDurationMinutes())));
            }

            userRepository.save(user);
            throw new UnauthorizedException("Invalid credentials");
        }

        if (!user.isVerified()) {
            throw new UnauthorizedException("Please verify your email before logging in");
        }

        // Reset failed attempts on successful login
        if (user.getFailedLoginAttempts() > 0) {
            user.setFailedLoginAttempts(0);
            user.setLockoutUntil(null);
            userRepository.save(user);
        }

        // Generate tokens
        String accessToken = jwtTokenProvider.generateAccessToken(user.getId());
        String refreshToken = jwtTokenProvider.generateRefreshToken(user.getId());

        // Session management
        String deviceInfo = sessionService.getDeviceInfo(httpRequest);
        String ipAddress = sessionService.getClientIp(httpRequest);
        Duration refreshExpiry = appProperties.getJwt().getRefreshToken().getExpiresIn();
        Instant expiresAt = Instant.now().plus(refreshExpiry);

        boolean sessionUpdated = sessionService.updateExistingSession(
                user.getId(), deviceInfo, refreshToken, ipAddress, expiresAt);

        if (!sessionUpdated) {
            sessionService.enforceDeviceLimit(user.getId());

            RefreshToken newToken = new RefreshToken();
            newToken.setToken(refreshToken);
            newToken.setUser(user.getId());
            newToken.setDeviceInfo(deviceInfo);
            newToken.setIpAddress(ipAddress);
            newToken.setIssuedAt(Instant.now());
            newToken.setLastUsed(Instant.now());
            newToken.setExpiresAt(expiresAt);
            refreshTokenRepository.save(newToken);
        }

        // Set cookies
        cookieUtil.setAccessTokenCookie(httpResponse, accessToken);
        cookieUtil.setRefreshTokenCookie(httpResponse, refreshToken, refreshExpiry.getSeconds());

        return ApiResponse.success("User logged in successfully", UserResponse.from(user));
    }

    @Override
    public ApiResponse<Void> refreshToken(HttpServletRequest request, HttpServletResponse response) {
        String tokenFromCookie = jwtTokenProvider.extractRefreshTokenFromRequest(request);
        if (tokenFromCookie == null) {
            throw new UnauthorizedException("No refresh token found");
        }

        RefreshToken refreshTokenDoc = refreshTokenRepository.findByToken(tokenFromCookie)
                .orElseThrow(() -> new UnauthorizedException("Invalid refresh token"));

        if (Instant.now().isAfter(refreshTokenDoc.getExpiresAt())) {
            refreshTokenRepository.deleteById(refreshTokenDoc.getId());
            throw new UnauthorizedException("Refresh token has expired");
        }

        User user = userRepository.findById(refreshTokenDoc.getUser())
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        // Rotate tokens
        String newRefreshToken = jwtTokenProvider.generateRefreshToken(user.getId());
        String newAccessToken = jwtTokenProvider.generateAccessToken(user.getId());

        Duration refreshExpiry = appProperties.getJwt().getRefreshToken().getExpiresIn();
        Instant newExpiresAt = Instant.now().plus(refreshExpiry);

        // Bug #9 fix: use IpAddressUtil (modern, not deprecated)
        refreshTokenDoc.setToken(newRefreshToken);
        refreshTokenDoc.setLastUsed(Instant.now());
        refreshTokenDoc.setIpAddress(sessionService.getClientIp(request));
        refreshTokenDoc.setExpiresAt(newExpiresAt);
        refreshTokenRepository.save(refreshTokenDoc);

        // Set new cookies
        cookieUtil.setAccessTokenCookie(response, newAccessToken);
        cookieUtil.setRefreshTokenCookie(response, newRefreshToken, refreshExpiry.getSeconds());

        return ApiResponse.success("Tokens refreshed successfully");
    }

    @Override
    public ApiResponse<UserResponse> getProfile(String userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));
        return ApiResponse.success("User profile", UserResponse.from(user));
    }

    @Override
    public ApiResponse<Void> forgotPassword(ForgotPasswordRequest request) {
        // Bug #4 fix: always return generic response to prevent user enumeration
        String email = request.getEmail().toLowerCase().trim();
        User user = userRepository.findByEmail(email).orElse(null);

        if (user != null) {
            String token = secureTokenUtil.generateToken();
            user.setPasswordResetToken(token);
            user.setPasswordResetTokenTime(Instant.now().plus(Duration.ofMinutes(10)));
            userRepository.save(user);

            try {
                emailService.sendPasswordResetEmail(user.getEmail(), token);
            } catch (EmailSendException e) {
                log.warn("Password reset email could not be sent for: {}", email);
            }
        }

        return ApiResponse.success(
                "If an account with that email exists, a password reset link has been sent");
    }

    @Override
    public ApiResponse<Void> resetPassword(String token, ResetPasswordRequest request) {
        if (token == null || token.isBlank()) {
            throw new BadRequestException("Reset token is required");
        }

        User user = userRepository.findByPasswordResetTokenAndPasswordResetTokenTimeAfter(
                        token, Instant.now())
                .orElseThrow(() -> new BadRequestException("Invalid or expired reset token"));

        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setPasswordResetToken(null);
        user.setPasswordResetTokenTime(null);
        userRepository.save(user);

        return ApiResponse.success("Password reset successful. Please login with your new password");
    }

    @Override
    public ApiResponse<Void> logout(HttpServletRequest request, HttpServletResponse response) {
        String accessToken = jwtTokenProvider.extractTokenFromRequest(request);
        String refreshToken = jwtTokenProvider.extractRefreshTokenFromRequest(request);

        if (refreshToken != null) {
            refreshTokenRepository.deleteByToken(refreshToken);
        }

        if (accessToken != null) {
            tokenBlacklistService.blacklist(accessToken);
        }

        cookieUtil.clearTokenCookies(response);

        return ApiResponse.success("Logout successfully");
    }
}
