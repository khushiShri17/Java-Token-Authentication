package com.auth.tokensystem.dto;

import com.auth.tokensystem.dto.response.ApiResponse;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.*;

class ApiResponseTest {

    @Test
    @DisplayName("Bug #5: success response has correct shape")
    void successWithoutData() {
        ApiResponse<Void> response = ApiResponse.success("Operation done");

        assertThat(response.isSuccess()).isTrue();
        assertThat(response.getMessage()).isEqualTo("Operation done");
        assertThat(response.getData()).isNull();
        assertThat(response.getErrors()).isNull();
        assertThat(response.getTimestamp()).isNotNull();
    }

    @Test
    @DisplayName("Bug #5: success response with data has correct shape")
    void successWithData() {
        ApiResponse<String> response = ApiResponse.success("Found", "result");

        assertThat(response.isSuccess()).isTrue();
        assertThat(response.getMessage()).isEqualTo("Found");
        assertThat(response.getData()).isEqualTo("result");
        assertThat(response.getErrors()).isNull();
    }

    @Test
    @DisplayName("Bug #5: error response without details")
    void errorWithoutDetails() {
        ApiResponse<Void> response = ApiResponse.error("Something broke");

        assertThat(response.isSuccess()).isFalse();
        assertThat(response.getMessage()).isEqualTo("Something broke");
        assertThat(response.getData()).isNull();
        assertThat(response.getErrors()).isNull();
    }

    @Test
    @DisplayName("Bug #5: error response with validation errors")
    void errorWithDetails() {
        Map<String, String> errors = Map.of("email", "Invalid email");
        ApiResponse<Void> response = ApiResponse.error("Validation errors", errors);

        assertThat(response.isSuccess()).isFalse();
        assertThat(response.getMessage()).isEqualTo("Validation errors");
        assertThat(response.getErrors()).isEqualTo(errors);
    }
}
