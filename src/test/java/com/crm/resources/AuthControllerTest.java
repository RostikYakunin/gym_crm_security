package com.crm.resources;

import com.crm.init.DataInitializer;
import com.crm.models.AuthRequest;
import com.crm.models.Token;
import com.crm.services.security.BruteForceService;
import com.crm.services.security.CustomUserDetailsService;
import com.crm.services.security.JwtService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@ActiveProfiles("test")
@AutoConfigureMockMvc
@WithMockUser
class AuthControllerTest {
    @Autowired
    private MockMvc mockMvc;
    @MockitoBean
    private AuthenticationManager authenticationManager;
    @MockitoBean
    private JwtService jwtService;
    @MockitoBean
    private CustomUserDetailsService userDetailsService;
    @MockitoBean
    private BruteForceService bruteForceService;
    @MockitoBean
    private DataInitializer dataInitializer;

    private static final String LOGIN_URL = "/api/v1/auth/login";
    private static final String LOGOUT_URL = "/api/v1/auth/logout";

    @Test
    @DisplayName("Should login successfully with valid credentials")
    void testLogin_Success() throws Exception {
        // Given
        var authRequest = new AuthRequest("testuser", "testpassword");

        when(authenticationManager.authenticate(any())).thenReturn(null);
        when(userDetailsService.loadUserByUsername("testuser")).thenReturn(mock(UserDetails.class));
        when(jwtService.generateToken(any(UserDetails.class))).thenReturn(new Token());

        // When - Then
        mockMvc.perform(post(LOGIN_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(new ObjectMapper().writeValueAsString(authRequest)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$").value(new Token()));
    }

    @Test
    @DisplayName("Should failure login with invalid credentials")
    void testLogin_InvalidCredentials() throws Exception {
        // Given
        var authRequest = new AuthRequest("testuser", "wrongpassword");
        when(authenticationManager.authenticate(any())).thenThrow(BadCredentialsException.class);
        doNothing().when(bruteForceService).loginFailed(anyString());

        // When - Then
        mockMvc.perform(post(LOGIN_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(new ObjectMapper().writeValueAsString(authRequest)))
                .andExpect(status().isBadRequest())
                .andExpect(content().string("Authentication failed, please check your inputted data!"));
    }

    @Test
    @DisplayName("Should block the user due to too many failed attempts")
    void testLogin_UserBlocked() throws Exception {
        // Given
        var authRequest = new AuthRequest("testUserName", "testpassword");
        when(bruteForceService.isBlocked("testUserName")).thenReturn(true);

        // When - Then
        mockMvc.perform(post(LOGIN_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(new ObjectMapper().writeValueAsString(authRequest)))
                .andExpect(status().is(401))
                .andExpect(content().string("Authentication failed:User is temporarily blocked. Try again later."));
    }

    @Test
    @DisplayName("Should logout successfully with valid token")
    void testLogout_Success() throws Exception {
        // Given
        var authHeader = "Bearer ";
        doNothing().when(bruteForceService).logout(anyString());

        //When - Then
        mockMvc.perform(post(LOGOUT_URL)
                        .header("Authorization", authHeader))
                .andExpect(status().isOk())
                .andExpect(content().string("Logged out successfully"));
    }

    @Test
    @DisplayName("Should failure logout with invalid authorization header")
    void testLogout_InvalidCredentials() throws Exception {
        //Given
        var authHeader = "InvalidHeader";

        //When - Then
        mockMvc.perform(post(LOGOUT_URL)
                        .header("Authorization", authHeader))
                .andExpect(status().isBadRequest())
                .andExpect(content().string("Authentication failed, please check your inputted data!"));
    }
}