package com.auth.tokensystem.validation;

import jakarta.validation.ConstraintValidatorContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

class StrongPasswordValidatorTest {

    private StrongPasswordValidator validator;
    private ConstraintValidatorContext context;

    @BeforeEach
    void setUp() {
        validator = new StrongPasswordValidator();
        context = mock(ConstraintValidatorContext.class);
    }

    // --- Valid passwords ---

    @ParameterizedTest
    @ValueSource(strings = {
            "Password1!",
            "Str0ng@Pass",
            "MyP@ss1word",
            "Abcdefg1!",
            "Test1234&",
            "C0mpl3x!Pwd"
    })
    @DisplayName("should accept valid strong passwords")
    void validPasswords(String password) {
        assertThat(validator.isValid(password, context)).isTrue();
    }

    // --- Invalid: missing special character (Bug #3) ---

    @Test
    @DisplayName("Bug #3: should reject password without special character")
    void rejectsNoSpecialChar() {
        assertThat(validator.isValid("Password1", context)).isFalse();
    }

    @Test
    @DisplayName("Bug #3: should reject password with only letters and digits")
    void rejectsOnlyAlphanumeric() {
        assertThat(validator.isValid("Abcdef12", context)).isFalse();
    }

    // --- Invalid: too short (Bug #7) ---

    @Test
    @DisplayName("Bug #7: should reject password shorter than 8 characters")
    void rejectsTooShort() {
        assertThat(validator.isValid("Pa1!", context)).isFalse();
    }

    @Test
    @DisplayName("Bug #7: should reject 7-character password")
    void rejectsSevenChars() {
        assertThat(validator.isValid("Pass1!a", context)).isFalse();
    }

    // --- Invalid: missing uppercase ---

    @Test
    @DisplayName("should reject password without uppercase letter")
    void rejectsNoUppercase() {
        assertThat(validator.isValid("password1!", context)).isFalse();
    }

    // --- Invalid: missing lowercase ---

    @Test
    @DisplayName("should reject password without lowercase letter")
    void rejectsNoLowercase() {
        assertThat(validator.isValid("PASSWORD1!", context)).isFalse();
    }

    // --- Invalid: missing digit ---

    @Test
    @DisplayName("should reject password without digit")
    void rejectsNoDigit() {
        assertThat(validator.isValid("Password!", context)).isFalse();
    }

    // --- Null and empty ---

    @ParameterizedTest
    @NullAndEmptySource
    @DisplayName("should reject null and empty passwords")
    void rejectsNullAndEmpty(String password) {
        assertThat(validator.isValid(password, context)).isFalse();
    }

    @Test
    @DisplayName("should reject blank/whitespace-only password")
    void rejectsBlank() {
        assertThat(validator.isValid("        ", context)).isFalse();
    }

    // --- Edge cases ---

    @Test
    @DisplayName("should accept password with exactly 8 characters meeting all criteria")
    void acceptsExactlyEightChars() {
        assertThat(validator.isValid("Abcde1!f", context)).isTrue();
    }

    @Test
    @DisplayName("should accept all allowed special characters")
    void acceptsAllSpecialChars() {
        assertThat(validator.isValid("Aa1@test", context)).isTrue();
        assertThat(validator.isValid("Aa1$test", context)).isTrue();
        assertThat(validator.isValid("Aa1!test", context)).isTrue();
        assertThat(validator.isValid("Aa1%test", context)).isTrue();
        assertThat(validator.isValid("Aa1*test", context)).isTrue();
        assertThat(validator.isValid("Aa1?test", context)).isTrue();
        assertThat(validator.isValid("Aa1&test", context)).isTrue();
    }
}
