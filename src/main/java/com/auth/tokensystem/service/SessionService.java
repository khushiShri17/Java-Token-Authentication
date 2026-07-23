package com.auth.tokensystem.service;

import com.auth.tokensystem.dto.response.SessionResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.time.Instant;
import java.util.List;

public interface SessionService {

    String getDeviceInfo(HttpServletRequest request);

    String getClientIp(HttpServletRequest request);

    boolean updateExistingSession(String userId, String deviceInfo, String refreshToken,
                                  String ipAddress, Instant expiryDate);

    void enforceDeviceLimit(String userId);

    List<SessionResponse> getActiveSessions(String userId, String currentRefreshToken);

    long logoutAllOtherDevices(String userId, String currentRefreshToken);

    void terminateSession(String sessionId, String userId, String currentRefreshToken,
                          HttpServletRequest request, HttpServletResponse response);
}
