package com.auth.tokensystem.security;

import com.auth.tokensystem.model.User;
import com.auth.tokensystem.repository.UserRepository;
import com.auth.tokensystem.service.TokenBlacklistService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Optional;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class JwtAuthenticationFilterTest {

    @Mock private JwtTokenProvider jwtTokenProvider;
    @Mock private UserRepository userRepository;
    @Mock private TokenBlacklistService tokenBlacklistService;
    @Mock private HttpServletRequest request;
    @Mock private HttpServletResponse response;
    @Mock private FilterChain filterChain;

    @InjectMocks
    private JwtAuthenticationFilter jwtAuthenticationFilter;

    @BeforeEach
    void setUp() {
        SecurityContextHolder.clearContext();
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    @DisplayName("should set authentication for valid, non-blacklisted token")
    void validToken_SetsAuth() throws Exception {
        User user = new User();
        user.setId("user1");
        user.setRole(User.Role.USER);

        when(jwtTokenProvider.extractTokenFromRequest(request)).thenReturn("valid-token");
        when(tokenBlacklistService.isBlacklisted("valid-token")).thenReturn(false);
        when(jwtTokenProvider.validateAccessToken("valid-token")).thenReturn(true);
        when(jwtTokenProvider.getUserIdFromAccessToken("valid-token")).thenReturn("user1");
        when(userRepository.findById("user1")).thenReturn(Optional.of(user));

        jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
        assertThat(SecurityContextHolder.getContext().getAuthentication().getPrincipal()).isEqualTo(user);
        verify(filterChain).doFilter(request, response);
    }

    @Test
    @DisplayName("should set ROLE_ authority based on user role")
    void validToken_SetsRoleAuthority() throws Exception {
        User admin = new User();
        admin.setId("admin1");
        admin.setRole(User.Role.ADMIN);

        when(jwtTokenProvider.extractTokenFromRequest(request)).thenReturn("admin-token");
        when(tokenBlacklistService.isBlacklisted("admin-token")).thenReturn(false);
        when(jwtTokenProvider.validateAccessToken("admin-token")).thenReturn(true);
        when(jwtTokenProvider.getUserIdFromAccessToken("admin-token")).thenReturn("admin1");
        when(userRepository.findById("admin1")).thenReturn(Optional.of(admin));

        jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

        var auth = SecurityContextHolder.getContext().getAuthentication();
        assertThat(auth.getAuthorities())
                .extracting("authority")
                .containsExactly("ROLE_ADMIN");
    }

    @Test
    @DisplayName("should not authenticate when token is blacklisted")
    void blacklistedToken_SkipsAuth() throws Exception {
        when(jwtTokenProvider.extractTokenFromRequest(request)).thenReturn("blacklisted-token");
        when(tokenBlacklistService.isBlacklisted("blacklisted-token")).thenReturn(true);

        jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        verify(filterChain).doFilter(request, response);
    }

    @Test
    @DisplayName("should not authenticate when token is invalid")
    void invalidToken_SkipsAuth() throws Exception {
        when(jwtTokenProvider.extractTokenFromRequest(request)).thenReturn("invalid-token");
        when(tokenBlacklistService.isBlacklisted("invalid-token")).thenReturn(false);
        when(jwtTokenProvider.validateAccessToken("invalid-token")).thenReturn(false);

        jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        verify(filterChain).doFilter(request, response);
    }

    @Test
    @DisplayName("should not authenticate when no token present")
    void noToken_SkipsAuth() throws Exception {
        when(jwtTokenProvider.extractTokenFromRequest(request)).thenReturn(null);

        jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        verify(filterChain).doFilter(request, response);
    }

    @Test
    @DisplayName("should not authenticate when user not found in DB")
    void userNotFound_SkipsAuth() throws Exception {
        when(jwtTokenProvider.extractTokenFromRequest(request)).thenReturn("valid-token");
        when(tokenBlacklistService.isBlacklisted("valid-token")).thenReturn(false);
        when(jwtTokenProvider.validateAccessToken("valid-token")).thenReturn(true);
        when(jwtTokenProvider.getUserIdFromAccessToken("valid-token")).thenReturn("deleted-user");
        when(userRepository.findById("deleted-user")).thenReturn(Optional.empty());

        jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        verify(filterChain).doFilter(request, response);
    }

    @Test
    @DisplayName("should always call filterChain.doFilter regardless of auth outcome")
    void alwaysCallsFilterChain() throws Exception {
        when(jwtTokenProvider.extractTokenFromRequest(request)).thenReturn(null);

        jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

        verify(filterChain, times(1)).doFilter(request, response);
    }
}
