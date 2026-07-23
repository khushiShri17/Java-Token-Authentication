package com.auth.tokensystem.model;

import lombok.Getter;
import lombok.Setter;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;

import java.time.Instant;

@Getter
@Setter
@Document(collection = "blacklisted_tokens")
public class BlacklistedToken {

    @Id
    private String id;

    @Indexed(unique = true)
    private String token;

    private String user;

    @Indexed(expireAfterSeconds = 0)
    private Instant expiresAt;
}
