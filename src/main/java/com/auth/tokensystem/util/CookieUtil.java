package com.auth.tokensystem.util;

import com.auth.tokensystem.config.AppProperties;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

@Component
public class CookieUtil {

    private final AppProperties appProperties;
    private final boolean isProduction;

    public CookieUtil(AppProperties appProperties,
                      @Value("${spring.profiles.active:development}") String activeProfile) {
        this.appProperties = appProperties;
        this.isProduction = "production".equalsIgnoreCase(activeProfile);
    }

    public void setAccessTokenCookie(HttpServletResponse response, String token) {
        long maxAge = appProperties.getJwt().getAccessToken().getExpiresIn().getSeconds();
        ResponseCookie cookie = buildCookie("accessToken", token, maxAge);
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
    }

    public void setRefreshTokenCookie(HttpServletResponse response, String token, long maxAgeSeconds) {
        ResponseCookie cookie = buildCookie("refreshToken", token, maxAgeSeconds);
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
    }

    public void clearTokenCookies(HttpServletResponse response) {
        ResponseCookie clearAccess = buildCookie("accessToken", "", 0);
        ResponseCookie clearRefresh = buildCookie("refreshToken", "", 0);
        response.addHeader(HttpHeaders.SET_COOKIE, clearAccess.toString());
        response.addHeader(HttpHeaders.SET_COOKIE, clearRefresh.toString());
    }

    private ResponseCookie buildCookie(String name, String value, long maxAgeSeconds) {
        return ResponseCookie.from(name, value)
                .httpOnly(true)
                .secure(isProduction)
                .sameSite("Strict")
                .path("/")
                .maxAge(maxAgeSeconds)
                .build();
    }
}
