package com.auth.tokensystem.model;

import lombok.Getter;
import lombok.Setter;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.CompoundIndex;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;

import java.time.Instant;

@Getter
@Setter
@Document(collection = "refresh_tokens")
@CompoundIndex(name = "user_device_idx", def = "{'user': 1, 'deviceInfo': 1}")
public class RefreshToken {

    @Id
    private String id;

    @Indexed(unique = true)
    private String token;

    private String user;

    private String deviceInfo;

    private String ipAddress = "Unknown";

    private Instant issuedAt;

    private Instant lastUsed;

    @Indexed(expireAfterSeconds = 0)
    private Instant expiresAt;
}
