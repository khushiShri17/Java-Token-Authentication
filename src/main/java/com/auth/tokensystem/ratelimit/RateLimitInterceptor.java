package com.auth.tokensystem.ratelimit;

import com.auth.tokensystem.exception.TooManyRequestsException;
import com.auth.tokensystem.util.IpAddressUtil;
import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;

import java.time.Duration;
import java.util.concurrent.ConcurrentHashMap;

@Component
@RequiredArgsConstructor
public class RateLimitInterceptor implements HandlerInterceptor {

    private final IpAddressUtil ipAddressUtil;
    private final ConcurrentHashMap<String, Bucket> buckets = new ConcurrentHashMap<>();

    @Override
    public boolean preHandle(@NonNull HttpServletRequest request,
                             @NonNull HttpServletResponse response,
                             @NonNull Object handler) {
        if (!(handler instanceof HandlerMethod handlerMethod)) {
            return true;
        }

        RateLimit rateLimit = handlerMethod.getMethodAnnotation(RateLimit.class);
        if (rateLimit == null) {
            return true;
        }

        String ip = ipAddressUtil.getClientIp(request);
        String key = handlerMethod.getMethod().getName() + ":" + ip;

        Bucket bucket = buckets.computeIfAbsent(key, k ->
                Bucket.builder()
                        .addLimit(Bandwidth.builder()
                                .capacity(rateLimit.requests())
                                .refillGreedy(rateLimit.requests(), Duration.ofMinutes(rateLimit.windowMinutes()))
                                .build())
                        .build()
        );

        if (!bucket.tryConsume(1)) {
            throw new TooManyRequestsException(
                    "Too many requests from this IP, please try again after " +
                            rateLimit.windowMinutes() + " minutes."
            );
        }

        return true;
    }
}
