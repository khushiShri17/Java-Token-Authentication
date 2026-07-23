package com.auth.tokensystem.dto;

import com.auth.tokensystem.dto.response.UserResponse;
import com.auth.tokensystem.model.User;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.assertj.core.api.Assertions.*;

class UserResponseTest {

    @Test
    @DisplayName("should map User to UserResponse correctly")
    void fromUser() {
        User user = new User();
        user.setId("abc123");
        user.setName("Jane Doe");
        user.setEmail("jane@example.com");
        user.setRole(User.Role.USER);
        user.setVerified(true);
        user.setCreatedAt(Instant.parse("2026-01-15T10:00:00Z"));

        UserResponse dto = UserResponse.from(user);

        assertThat(dto.getId()).isEqualTo("abc123");
        assertThat(dto.getName()).isEqualTo("Jane Doe");
        assertThat(dto.getEmail()).isEqualTo("jane@example.com");
        assertThat(dto.getRole()).isEqualTo("user");
        assertThat(dto.isVerified()).isTrue();
        assertThat(dto.getCreatedAt()).isEqualTo(Instant.parse("2026-01-15T10:00:00Z"));
    }

    @Test
    @DisplayName("should map ADMIN role to lowercase")
    void adminRoleLowercase() {
        User admin = new User();
        admin.setId("admin1");
        admin.setName("Admin");
        admin.setEmail("admin@example.com");
        admin.setRole(User.Role.ADMIN);
        admin.setVerified(true);

        UserResponse dto = UserResponse.from(admin);

        assertThat(dto.getRole()).isEqualTo("admin");
    }
}
