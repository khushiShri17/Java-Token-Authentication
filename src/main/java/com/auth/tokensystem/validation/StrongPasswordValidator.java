package com.auth.tokensystem.validation;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

import java.util.regex.Pattern;

public class StrongPasswordValidator implements ConstraintValidator<StrongPassword, String> {

    // Bug #3 fix: includes (?=.*[@$!%*?&]) to enforce special character
    // Bug #7 fix: minimum 8 characters (not 6)
    private static final Pattern PASSWORD_PATTERN = Pattern.compile(
            "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[a-zA-Z\\d@$!%*?&]{8,}$"
    );

    @Override
    public boolean isValid(String password, ConstraintValidatorContext context) {
        if (password == null || password.isBlank()) {
            return false;
        }
        return PASSWORD_PATTERN.matcher(password).matches();
    }
}
