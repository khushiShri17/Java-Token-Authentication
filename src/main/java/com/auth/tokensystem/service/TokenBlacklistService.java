package com.auth.tokensystem.service;

import com.auth.tokensystem.model.BlacklistedToken;
import com.auth.tokensystem.repository.BlacklistedTokenRepository;
import com.auth.tokensystem.security.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.Instant;

@Service
@RequiredArgsConstructor
@Slf4j
public class TokenBlacklistService {

    private final BlacklistedTokenRepository blacklistedTokenRepository;
    private final JwtTokenProvider jwtTokenProvider;

    public void blacklist(String accessToken) {
        try {
            String userId = jwtTokenProvider.getUserIdFromAccessToken(accessToken);
            Instant expiresAt = jwtTokenProvider.getAccessTokenExpiration(accessToken);

            BlacklistedToken blacklisted = new BlacklistedToken();
            blacklisted.setToken(accessToken);
            blacklisted.setUser(userId);
            blacklisted.setExpiresAt(expiresAt);

            blacklistedTokenRepository.save(blacklisted);
        } catch (Exception e) {
            log.warn("Failed to blacklist access token: {}", e.getMessage());
        }
    }

    public boolean isBlacklisted(String token) {
        return blacklistedTokenRepository.existsByToken(token);
    }
}
