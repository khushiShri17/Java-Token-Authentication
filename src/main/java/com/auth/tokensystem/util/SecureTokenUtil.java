package com.auth.tokensystem.util;

import org.springframework.stereotype.Component;

import java.security.SecureRandom;

@Component
public class SecureTokenUtil {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    public String generateToken() {
        return generateToken(32);
    }

    public String generateToken(int bytes) {
        byte[] tokenBytes = new byte[bytes];
        SECURE_RANDOM.nextBytes(tokenBytes);
        StringBuilder hex = new StringBuilder(bytes * 2);
        for (byte b : tokenBytes) {
            hex.append(String.format("%02x", b));
        }
        return hex.toString();
    }
}
