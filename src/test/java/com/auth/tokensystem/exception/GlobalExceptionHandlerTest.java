package com.auth.tokensystem.exception;

import com.auth.tokensystem.dto.response.ApiResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.core.MethodParameter;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BeanPropertyBindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;

import java.util.Map;

import static org.assertj.core.api.Assertions.*;

class GlobalExceptionHandlerTest {

    private GlobalExceptionHandler handler;

    @BeforeEach
    void setUp() {
        handler = new GlobalExceptionHandler();
    }

    @Test
    @DisplayName("should handle validation errors with field-level messages")
    void handleValidation() throws Exception {
        BeanPropertyBindingResult bindingResult = new BeanPropertyBindingResult(new Object(), "request");
        bindingResult.addError(new FieldError("request", "email", "Please enter a valid email"));
        bindingResult.addError(new FieldError("request", "password", "Password is required"));

        MethodParameter param = new MethodParameter(
                GlobalExceptionHandlerTest.class.getDeclaredMethod("handleValidation"), -1);
        MethodArgumentNotValidException ex = new MethodArgumentNotValidException(param, bindingResult);

        ResponseEntity<ApiResponse<Void>> response = handler.handleValidation(ex);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().isSuccess()).isFalse();
        assertThat(response.getBody().getMessage()).isEqualTo("Validation errors");

        @SuppressWarnings("unchecked")
        Map<String, String> errors = (Map<String, String>) response.getBody().getErrors();
        assertThat(errors).containsEntry("email", "Please enter a valid email");
        assertThat(errors).containsEntry("password", "Password is required");
    }

    @Test
    @DisplayName("should return 400 for BadRequestException")
    void handleBadRequest() {
        ResponseEntity<ApiResponse<Void>> response =
                handler.handleBadRequest(new BadRequestException("Bad input"));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(response.getBody().getMessage()).isEqualTo("Bad input");
    }

    @Test
    @DisplayName("should return 401 for UnauthorizedException")
    void handleUnauthorized() {
        ResponseEntity<ApiResponse<Void>> response =
                handler.handleUnauthorized(new UnauthorizedException("Not authorized"));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(response.getBody().getMessage()).isEqualTo("Not authorized");
    }

    @Test
    @DisplayName("should return 403 for ForbiddenException")
    void handleForbidden() {
        ResponseEntity<ApiResponse<Void>> response =
                handler.handleForbidden(new ForbiddenException("Access denied"));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }

    @Test
    @DisplayName("should return 404 for ResourceNotFoundException")
    void handleNotFound() {
        ResponseEntity<ApiResponse<Void>> response =
                handler.handleNotFound(new ResourceNotFoundException("User not found"));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
    }

    @Test
    @DisplayName("should return 409 for ConflictException")
    void handleConflict() {
        ResponseEntity<ApiResponse<Void>> response =
                handler.handleConflict(new ConflictException("Already exists"));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
    }

    @Test
    @DisplayName("should return 429 for TooManyRequestsException")
    void handleTooManyRequests() {
        ResponseEntity<ApiResponse<Void>> response =
                handler.handleTooManyRequests(new TooManyRequestsException("Rate limited"));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.TOO_MANY_REQUESTS);
    }

    @Test
    @DisplayName("Bug #11: should return 423 for AccountLockedException")
    void handleAccountLocked() {
        ResponseEntity<ApiResponse<Void>> response =
                handler.handleAccountLocked(new AccountLockedException("Account locked"));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.LOCKED);
    }

    @Test
    @DisplayName("Bug #8: should return 502 for EmailSendException")
    void handleEmailSend() {
        ResponseEntity<ApiResponse<Void>> response =
                handler.handleEmailSend(new EmailSendException("SMTP failure"));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_GATEWAY);
        assertThat(response.getBody().getMessage()).isEqualTo("SMTP failure");
    }

    @Test
    @DisplayName("should return 500 for unhandled exceptions")
    void handleGeneral() {
        ResponseEntity<ApiResponse<Void>> response =
                handler.handleGeneral(new RuntimeException("unexpected"));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
        assertThat(response.getBody().getMessage()).isEqualTo("Internal server error");
    }

    @Test
    @DisplayName("Bug #5: all error responses have consistent shape")
    void consistentErrorShape() {
        ResponseEntity<ApiResponse<Void>> response =
                handler.handleBadRequest(new BadRequestException("test"));

        ApiResponse<Void> body = response.getBody();
        assertThat(body).isNotNull();
        assertThat(body.isSuccess()).isFalse();
        assertThat(body.getMessage()).isNotNull();
        assertThat(body.getTimestamp()).isNotNull();
    }
}
