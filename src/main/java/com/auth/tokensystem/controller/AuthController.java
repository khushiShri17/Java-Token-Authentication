package com.auth.tokensystem.controller;

import com.auth.tokensystem.dto.request.*;
import com.auth.tokensystem.dto.response.ApiResponse;
import com.auth.tokensystem.dto.response.SessionResponse;
import com.auth.tokensystem.dto.response.UserResponse;
import com.auth.tokensystem.exception.BadRequestException;
import com.auth.tokensystem.model.User;
import com.auth.tokensystem.ratelimit.RateLimit;
import com.auth.tokensystem.security.JwtTokenProvider;
import com.auth.tokensystem.service.AuthService;
import com.auth.tokensystem.service.SessionService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/users")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final SessionService sessionService;
    private final JwtTokenProvider jwtTokenProvider;

    // --- Public Endpoints ---

    @PostMapping("/register")
    @RateLimit(requests = 100, windowMinutes = 15)
    public ResponseEntity<ApiResponse<UserResponse>> register(@Valid @RequestBody RegisterRequest request) {
        ApiResponse<UserResponse> response = authService.register(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @PostMapping("/login")
    @RateLimit(requests = 5, windowMinutes = 15)
    public ResponseEntity<ApiResponse<UserResponse>> login(@Valid @RequestBody LoginRequest request,
                                                            HttpServletRequest httpRequest,
                                                            HttpServletResponse httpResponse) {
        return ResponseEntity.ok(authService.login(request, httpRequest, httpResponse));
    }

    // Bug #6 fix: rate limiting on verify endpoint
    @GetMapping("/verify/{token}")
    @RateLimit(requests = 100, windowMinutes = 15)
    public ResponseEntity<ApiResponse<Void>> verifyEmail(@PathVariable String token) {
        return ResponseEntity.ok(authService.verifyEmail(token));
    }

    @PostMapping("/forgot-password")
    @RateLimit(requests = 100, windowMinutes = 15)
    public ResponseEntity<ApiResponse<Void>> forgotPassword(@Valid @RequestBody ForgotPasswordRequest request) {
        return ResponseEntity.ok(authService.forgotPassword(request));
    }

    @PutMapping("/reset-password/{token}")
    @RateLimit(requests = 100, windowMinutes = 15)
    public ResponseEntity<ApiResponse<Void>> resetPassword(@PathVariable String token,
                                                            @Valid @RequestBody ResetPasswordRequest request) {
        return ResponseEntity.ok(authService.resetPassword(token, request));
    }

    // Bug #2 fix: rate limiting on refresh-token endpoint
    @PostMapping("/refresh-token")
    @RateLimit(requests = 20, windowMinutes = 15)
    public ResponseEntity<ApiResponse<Void>> refreshToken(HttpServletRequest request,
                                                           HttpServletResponse response) {
        return ResponseEntity.ok(authService.refreshToken(request, response));
    }

    // --- Protected Endpoints ---

    @GetMapping("/profile")
    public ResponseEntity<ApiResponse<UserResponse>> getProfile(@AuthenticationPrincipal User user) {
        return ResponseEntity.ok(authService.getProfile(user.getId()));
    }

    @GetMapping("/sessions")
    public ResponseEntity<ApiResponse<Map<String, List<SessionResponse>>>> getActiveSessions(
            @AuthenticationPrincipal User user, HttpServletRequest request) {
        String currentRefreshToken = jwtTokenProvider.extractRefreshTokenFromRequest(request);
        List<SessionResponse> sessions = sessionService.getActiveSessions(user.getId(), currentRefreshToken);
        return ResponseEntity.ok(ApiResponse.success("Active sessions retrieved",
                Map.of("sessions", sessions)));
    }

    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<Void>> logout(HttpServletRequest request,
                                                     HttpServletResponse response) {
        return ResponseEntity.ok(authService.logout(request, response));
    }

    @PostMapping("/logout-all-other-devices")
    public ResponseEntity<ApiResponse<Map<String, Long>>> logoutAllOtherDevices(
            @AuthenticationPrincipal User user, HttpServletRequest request) {
        String currentRefreshToken = jwtTokenProvider.extractRefreshTokenFromRequest(request);
        long deletedCount = sessionService.logoutAllOtherDevices(user.getId(), currentRefreshToken);
        return ResponseEntity.ok(ApiResponse.success("Logout from all other devices successful",
                Map.of("deletedSessions", deletedCount)));
    }

    @DeleteMapping("/sessions/{sessionId}")
    public ResponseEntity<ApiResponse<Void>> terminateSession(
            @PathVariable String sessionId,
            @AuthenticationPrincipal User user,
            HttpServletRequest request,
            HttpServletResponse response) {
        String currentRefreshToken = jwtTokenProvider.extractRefreshTokenFromRequest(request);
        try {
            sessionService.terminateSession(sessionId, user.getId(), currentRefreshToken, request, response);
            return ResponseEntity.ok(ApiResponse.success("Session terminated successfully"));
        } catch (BadRequestException e) {
            if ("CURRENT_SESSION".equals(e.getMessage())) {
                // Terminating current session = full logout
                return ResponseEntity.ok(authService.logout(request, response));
            }
            throw e;
        }
    }

    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<Map<String, UserResponse>>> adminEndpoint(
            @AuthenticationPrincipal User user) {
        return ResponseEntity.ok(ApiResponse.success("Admin access granted",
                Map.of("user", UserResponse.from(user))));
    }
}
