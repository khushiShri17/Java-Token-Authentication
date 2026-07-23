package com.auth.tokensystem;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import com.auth.tokensystem.config.AppProperties;

@SpringBootApplication
@EnableConfigurationProperties(AppProperties.class)
public class TokenAuthenticationSystemApplication {

    public static void main(String[] args) {
        SpringApplication.run(TokenAuthenticationSystemApplication.class, args);
    }
}
