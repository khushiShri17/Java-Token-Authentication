package com.auth.tokensystem.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

@Getter
@Setter
@ConfigurationProperties(prefix = "app")
public class AppProperties {

    private final Jwt jwt = new Jwt();
    private final Security security = new Security();
    private final Urls urls = new Urls();
    private final Mail mail = new Mail();

    @Getter
    @Setter
    public static class Jwt {
        private final TokenConfig accessToken = new TokenConfig();
        private final TokenConfig refreshToken = new TokenConfig();

        @Getter
        @Setter
        public static class TokenConfig {
            private String secret;
            private Duration expiresIn = Duration.ofMinutes(15);
        }
    }

    @Getter
    @Setter
    public static class Security {
        private int maxDevicesPerUser = 2;
        private int maxLoginAttempts = 5;
        private int lockoutDurationMinutes = 30;
    }

    @Getter
    @Setter
    public static class Urls {
        private String base = "http://localhost:5000";
        private String frontend = "http://localhost:3000";
    }

    @Getter
    @Setter
    public static class Mail {
        private String senderEmail;
    }
}
