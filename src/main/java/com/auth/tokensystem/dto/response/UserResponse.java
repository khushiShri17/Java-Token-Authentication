package com.auth.tokensystem.dto.response;

import com.auth.tokensystem.model.User;
import lombok.Getter;
import lombok.Setter;

import java.time.Instant;

@Getter
@Setter
public class UserResponse {

    private String id;
    private String name;
    private String email;
    private String role;
    private boolean isVerified;
    private Instant createdAt;

    public static UserResponse from(User user) {
        UserResponse dto = new UserResponse();
        dto.setId(user.getId());
        dto.setName(user.getName());
        dto.setEmail(user.getEmail());
        dto.setRole(user.getRole().name().toLowerCase());
        dto.setVerified(user.isVerified());
        dto.setCreatedAt(user.getCreatedAt());
        return dto;
    }
}
