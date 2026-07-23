package com.auth.tokensystem.ratelimit;

import com.auth.tokensystem.exception.TooManyRequestsException;
import com.auth.tokensystem.util.IpAddressUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.web.method.HandlerMethod;

import java.lang.reflect.Method;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class RateLimitInterceptorTest {

    @Mock private IpAddressUtil ipAddressUtil;
    @Mock private HttpServletRequest request;
    @Mock private HttpServletResponse response;

    @InjectMocks
    private RateLimitInterceptor rateLimitInterceptor;

    // Dummy handler class with rate-limited and non-rate-limited methods
    static class TestHandler {
        @RateLimit(requests = 3, windowMinutes = 15)
        public void rateLimitedMethod() {}

        public void nonRateLimitedMethod() {}
    }

    private HandlerMethod createHandlerMethod(String methodName) throws Exception {
        Method method = TestHandler.class.getMethod(methodName);
        return new HandlerMethod(new TestHandler(), method);
    }

    @BeforeEach
    void setUp() {
        // Each test gets a fresh interceptor with empty bucket map
        rateLimitInterceptor = new RateLimitInterceptor(ipAddressUtil);
    }

    @Test
    @DisplayName("should allow requests within rate limit")
    void allowsWithinLimit() throws Exception {
        when(ipAddressUtil.getClientIp(request)).thenReturn("10.0.0.1");
        HandlerMethod handler = createHandlerMethod("rateLimitedMethod");

        assertThat(rateLimitInterceptor.preHandle(request, response, handler)).isTrue();
        assertThat(rateLimitInterceptor.preHandle(request, response, handler)).isTrue();
        assertThat(rateLimitInterceptor.preHandle(request, response, handler)).isTrue();
    }

    @Test
    @DisplayName("should throw TooManyRequestsException when limit exceeded")
    void throwsWhenLimitExceeded() throws Exception {
        when(ipAddressUtil.getClientIp(request)).thenReturn("10.0.0.2");
        HandlerMethod handler = createHandlerMethod("rateLimitedMethod");

        // Consume all 3 tokens
        rateLimitInterceptor.preHandle(request, response, handler);
        rateLimitInterceptor.preHandle(request, response, handler);
        rateLimitInterceptor.preHandle(request, response, handler);

        // 4th request should fail
        assertThatThrownBy(() -> rateLimitInterceptor.preHandle(request, response, handler))
                .isInstanceOf(TooManyRequestsException.class)
                .hasMessageContaining("Too many requests");
    }

    @Test
    @DisplayName("should not rate limit endpoints without @RateLimit annotation")
    void noAnnotation_AlwaysAllows() throws Exception {
        HandlerMethod handler = createHandlerMethod("nonRateLimitedMethod");

        // Should allow unlimited requests
        for (int i = 0; i < 100; i++) {
            assertThat(rateLimitInterceptor.preHandle(request, response, handler)).isTrue();
        }
    }

    @Test
    @DisplayName("should track rate limits per IP address")
    void perIpTracking() throws Exception {
        HandlerMethod handler = createHandlerMethod("rateLimitedMethod");

        // IP 1: consume all 3 tokens
        when(ipAddressUtil.getClientIp(request)).thenReturn("192.168.1.1");
        rateLimitInterceptor.preHandle(request, response, handler);
        rateLimitInterceptor.preHandle(request, response, handler);
        rateLimitInterceptor.preHandle(request, response, handler);

        // IP 2: should still have tokens
        when(ipAddressUtil.getClientIp(request)).thenReturn("192.168.1.2");
        assertThat(rateLimitInterceptor.preHandle(request, response, handler)).isTrue();
    }

    @Test
    @DisplayName("should pass through for non-HandlerMethod handlers (e.g., static resources)")
    void nonHandlerMethod_PassesThrough() {
        Object plainHandler = new Object();

        assertThat(rateLimitInterceptor.preHandle(request, response, plainHandler)).isTrue();
    }
}
