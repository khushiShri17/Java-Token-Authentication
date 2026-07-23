package com.auth.tokensystem.dto.request;

import com.auth.tokensystem.validation.StrongPassword;
import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class ResetPasswordRequest {

    @NotBlank(message = "Password is required")
    @StrongPassword
    private String password;
}
