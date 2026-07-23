package com.auth.tokensystem.service;

import com.auth.tokensystem.dto.request.*;
import com.auth.tokensystem.dto.response.ApiResponse;
import com.auth.tokensystem.dto.response.UserResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public interface AuthService {

    ApiResponse<UserResponse> register(RegisterRequest request);

    ApiResponse<Void> verifyEmail(String token);

    ApiResponse<UserResponse> login(LoginRequest request, HttpServletRequest httpRequest,
                                     HttpServletResponse httpResponse);

    ApiResponse<Void> refreshToken(HttpServletRequest request, HttpServletResponse response);

    ApiResponse<UserResponse> getProfile(String userId);

    ApiResponse<Void> forgotPassword(ForgotPasswordRequest request);

    ApiResponse<Void> resetPassword(String token, ResetPasswordRequest request);

    ApiResponse<Void> logout(HttpServletRequest request, HttpServletResponse response);
}
