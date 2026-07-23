package com.auth.tokensystem.model;

import lombok.Getter;
import lombok.Setter;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;

import java.time.Instant;

@Getter
@Setter
@Document(collection = "users")
public class User {

    @Id
    private String id;

    private String name;

    @Indexed(unique = true)
    private String email;

    private String password;

    private Role role = Role.USER;

    private boolean isVerified = false;

    private String verificationToken;
    private Instant verificationTokenTime;

    private String passwordResetToken;
    private Instant passwordResetTokenTime;

    // Account lockout fields (Bug #11 fix)
    private int failedLoginAttempts = 0;
    private Instant lockoutUntil;

    @CreatedDate
    private Instant createdAt;

    @LastModifiedDate
    private Instant updatedAt;

    public enum Role {
        USER, ADMIN
    }
}
