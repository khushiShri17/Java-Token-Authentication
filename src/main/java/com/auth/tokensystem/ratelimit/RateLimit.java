package com.auth.tokensystem.ratelimit;

import java.lang.annotation.*;

@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface RateLimit {

    int requests() default 100;

    int windowMinutes() default 15;
}
