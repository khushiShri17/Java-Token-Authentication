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
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@Slf4j
public class SessionServiceImpl implements SessionService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final AppProperties appProperties;
    private final IpAddressUtil ipAddressUtil;

    @Override
    public String getDeviceInfo(HttpServletRequest request) {
        String userAgent = request.getHeader("User-Agent");
        return (userAgent != null && !userAgent.isBlank()) ? userAgent : "Unknown device";
    }

    @Override
    public String getClientIp(HttpServletRequest request) {
        return ipAddressUtil.getClientIp(request);
    }

    @Override
    public boolean updateExistingSession(String userId, String deviceInfo,
                                         String refreshToken, String ipAddress,
                                         Instant expiryDate) {
        Optional<RefreshToken> existing = refreshTokenRepository
                .findByUserAndDeviceInfo(userId, deviceInfo);

        if (existing.isPresent()) {
            RefreshToken session = existing.get();
            session.setToken(refreshToken);
            session.setLastUsed(Instant.now());
            session.setIpAddress(ipAddress);
            session.setExpiresAt(expiryDate);
            refreshTokenRepository.save(session);
            return true;
        }
        return false;
    }

    @Override
    public void enforceDeviceLimit(String userId) {
        int maxDevices = appProperties.getSecurity().getMaxDevicesPerUser();
        long tokenCount = refreshTokenRepository.countByUser(userId);

        if (tokenCount >= maxDevices) {
            refreshTokenRepository.findFirstByUserOrderByLastUsedAsc(userId)
                    .ifPresent(oldest -> refreshTokenRepository.deleteById(oldest.getId()));
        }
    }

    @Override
    public List<SessionResponse> getActiveSessions(String userId, String currentRefreshToken) {
        List<RefreshToken> sessions = refreshTokenRepository.findByUserOrderByLastUsedDesc(userId);
        return sessions.stream()
                .map(session -> SessionResponse.from(session, currentRefreshToken != null ? currentRefreshToken : ""))
                .toList();
    }

    @Override
    public long logoutAllOtherDevices(String userId, String currentRefreshToken) {
        if (currentRefreshToken == null || currentRefreshToken.isBlank()) {
            throw new BadRequestException("No refresh token found");
        }

        long countBefore = refreshTokenRepository.countByUser(userId);
        refreshTokenRepository.deleteByUserAndTokenNot(userId, currentRefreshToken);
        long countAfter = refreshTokenRepository.countByUser(userId);
        return countBefore - countAfter;
    }

    @Override
    public void terminateSession(String sessionId, String userId, String currentRefreshToken,
                                 HttpServletRequest request, HttpServletResponse response) {
        RefreshToken session = refreshTokenRepository.findById(sessionId)
                .filter(s -> s.getUser().equals(userId))
                .orElseThrow(() -> new ResourceNotFoundException("Session not found"));

        if (session.getToken().equals(currentRefreshToken)) {
            // Terminating current session = full logout (handled by controller)
            throw new BadRequestException("CURRENT_SESSION");
        }

        refreshTokenRepository.deleteById(sessionId);
    }
}
