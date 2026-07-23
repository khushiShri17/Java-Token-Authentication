package com.auth.tokensystem.security;

import com.auth.tokensystem.config.AppProperties;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;

@Component
public class JwtTokenProvider {

    private final SecretKey accessTokenKey;
    private final SecretKey refreshTokenKey;
    private final Duration accessTokenExpiry;
    private final Duration refreshTokenExpiry;

    public JwtTokenProvider(AppProperties appProperties) {
        this.accessTokenKey = Keys.hmacShaKeyFor(
                appProperties.getJwt().getAccessToken().getSecret().getBytes(StandardCharsets.UTF_8));
        this.refreshTokenKey = Keys.hmacShaKeyFor(
                appProperties.getJwt().getRefreshToken().getSecret().getBytes(StandardCharsets.UTF_8));
        this.accessTokenExpiry = appProperties.getJwt().getAccessToken().getExpiresIn();
        this.refreshTokenExpiry = appProperties.getJwt().getRefreshToken().getExpiresIn();
    }

    public String generateAccessToken(String userId) {
        return buildToken(userId, accessTokenKey, accessTokenExpiry);
    }

    public String generateRefreshToken(String userId) {
        return buildToken(userId, refreshTokenKey, refreshTokenExpiry);
    }

    public Duration getRefreshTokenExpiry() {
        return refreshTokenExpiry;
    }

    public String getUserIdFromAccessToken(String token) {
        return parseClaims(token, accessTokenKey).get("id", String.class);
    }

    public String getUserIdFromRefreshToken(String token) {
        return parseClaims(token, refreshTokenKey).get("id", String.class);
    }

    public boolean validateAccessToken(String token) {
        return validateToken(token, accessTokenKey);
    }

    public Instant getAccessTokenExpiration(String token) {
        return parseClaims(token, accessTokenKey).getExpiration().toInstant();
    }

    public String extractTokenFromRequest(HttpServletRequest request) {
        // Priority 1: Cookie
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if ("accessToken".equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }

        // Priority 2: Authorization header
        String bearerToken = request.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }

        return null;
    }

    public String extractRefreshTokenFromRequest(HttpServletRequest request) {
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if ("refreshToken".equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }

    private String buildToken(String userId, SecretKey key, Duration expiry) {
        Instant now = Instant.now();
        return Jwts.builder()
                .claim("id", userId)
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plus(expiry)))
                .signWith(key)
                .compact();
    }

    private Claims parseClaims(String token, SecretKey key) {
        return Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    private boolean validateToken(String token, SecretKey key) {
        try {
            parseClaims(token, key);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }
}
