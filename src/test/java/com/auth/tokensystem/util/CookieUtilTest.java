package com.auth.tokensystem.util;

import com.auth.tokensystem.config.AppProperties;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.time.Duration;
import java.util.List;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

class CookieUtilTest {

    private CookieUtil cookieUtil;
    private HttpServletResponse response;

    @BeforeEach
    void setUp() {
        AppProperties props = new AppProperties();
        props.getJwt().getAccessToken().setExpiresIn(Duration.ofMinutes(15));

        cookieUtil = new CookieUtil(props, "development");
        response = mock(HttpServletResponse.class);
    }

    @Test
    @DisplayName("should set access token cookie with correct attributes")
    void setAccessTokenCookie() {
        cookieUtil.setAccessTokenCookie(response, "jwt-access-token");

        ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
        verify(response).addHeader(eq("Set-Cookie"), captor.capture());

        String cookie = captor.getValue();
        assertThat(cookie).contains("accessToken=jwt-access-token");
        assertThat(cookie).contains("HttpOnly");
        assertThat(cookie).contains("SameSite=Strict");
        assertThat(cookie).contains("Path=/");
    }

    @Test
    @DisplayName("should set refresh token cookie with correct attributes")
    void setRefreshTokenCookie() {
        cookieUtil.setRefreshTokenCookie(response, "jwt-refresh-token", 604800);

        ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
        verify(response).addHeader(eq("Set-Cookie"), captor.capture());

        String cookie = captor.getValue();
        assertThat(cookie).contains("refreshToken=jwt-refresh-token");
        assertThat(cookie).contains("HttpOnly");
        assertThat(cookie).contains("SameSite=Strict");
        assertThat(cookie).contains("Max-Age=604800");
    }

    @Test
    @DisplayName("should not set Secure flag in development mode")
    void noSecureFlagInDev() {
        cookieUtil.setAccessTokenCookie(response, "token");

        ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
        verify(response).addHeader(eq("Set-Cookie"), captor.capture());

        String cookie = captor.getValue();
        assertThat(cookie).doesNotContain("Secure");
    }

    @Test
    @DisplayName("should set Secure flag in production mode")
    void secureFlagInProduction() {
        AppProperties props = new AppProperties();
        props.getJwt().getAccessToken().setExpiresIn(Duration.ofMinutes(15));
        CookieUtil prodCookieUtil = new CookieUtil(props, "production");

        prodCookieUtil.setAccessTokenCookie(response, "token");

        ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
        verify(response).addHeader(eq("Set-Cookie"), captor.capture());

        String cookie = captor.getValue();
        assertThat(cookie).contains("Secure");
    }

    @Test
    @DisplayName("should clear both token cookies with Max-Age=0")
    void clearTokenCookies() {
        cookieUtil.clearTokenCookies(response);

        ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
        verify(response, times(2)).addHeader(eq("Set-Cookie"), captor.capture());

        List<String> cookies = captor.getAllValues();
        assertThat(cookies).hasSize(2);

        // Access token cleared
        assertThat(cookies.get(0)).contains("accessToken=");
        assertThat(cookies.get(0)).contains("Max-Age=0");

        // Refresh token cleared
        assertThat(cookies.get(1)).contains("refreshToken=");
        assertThat(cookies.get(1)).contains("Max-Age=0");
    }
}
