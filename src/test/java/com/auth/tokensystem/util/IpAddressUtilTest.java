package com.auth.tokensystem.util;

import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

class IpAddressUtilTest {

    private final IpAddressUtil ipAddressUtil = new IpAddressUtil();

    @Test
    @DisplayName("Bug #9: should extract first IP from X-Forwarded-For header")
    void extractsFromXForwardedFor() {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getHeader("X-Forwarded-For")).thenReturn("203.0.113.50, 70.41.3.18, 150.172.238.178");

        String ip = ipAddressUtil.getClientIp(request);

        assertThat(ip).isEqualTo("203.0.113.50");
    }

    @Test
    @DisplayName("Bug #9: should fall back to getRemoteAddr() when no X-Forwarded-For")
    void fallsBackToRemoteAddr() {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getHeader("X-Forwarded-For")).thenReturn(null);
        when(request.getRemoteAddr()).thenReturn("192.168.1.100");

        String ip = ipAddressUtil.getClientIp(request);

        assertThat(ip).isEqualTo("192.168.1.100");
    }

    @Test
    @DisplayName("should fall back to getRemoteAddr() when X-Forwarded-For is blank")
    void fallsBackWhenBlank() {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getHeader("X-Forwarded-For")).thenReturn("   ");
        when(request.getRemoteAddr()).thenReturn("10.0.0.1");

        String ip = ipAddressUtil.getClientIp(request);

        assertThat(ip).isEqualTo("10.0.0.1");
    }

    @Test
    @DisplayName("should handle single IP in X-Forwarded-For (no commas)")
    void singleIpInXForwardedFor() {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getHeader("X-Forwarded-For")).thenReturn("172.16.0.1");

        String ip = ipAddressUtil.getClientIp(request);

        assertThat(ip).isEqualTo("172.16.0.1");
    }

    @Test
    @DisplayName("should trim whitespace from X-Forwarded-For IP")
    void trimsWhitespace() {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getHeader("X-Forwarded-For")).thenReturn("  192.168.0.1  , 10.0.0.1");

        String ip = ipAddressUtil.getClientIp(request);

        assertThat(ip).isEqualTo("192.168.0.1");
    }
}
