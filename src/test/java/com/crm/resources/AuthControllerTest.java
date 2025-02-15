package com.crm.resources;

import com.crm.init.DataInitializer;
import com.crm.models.AuthRequest;
import com.crm.models.Token;
import com.crm.services.security.GymSecurityService;
import com.crm.services.security.JwtService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

import java.util.Date;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@ActiveProfiles("test")
@AutoConfigureMockMvc
class AuthControllerTest {
    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private ObjectMapper objectMapper;
    @MockitoBean
    private GymSecurityService securityService;
    @MockitoBean
    private DataInitializer dataInitializer;
    @MockitoBean
    private JwtService jwtService;


    private static final String LOGIN_URL = "/api/v1/auth/login";
    private static final String LOGOUT_URL = "/api/v1/auth/logout";

    @Test
    @DisplayName("Should return 201 and token on successful login")
    void shouldReturnTokenOnSuccessfulLogin() throws Exception {
        //Given
        var request = new AuthRequest("user", "Password1");
        var token = new Token("user", new Date(), new Date(), "jwt_token");
        when(securityService.login(any(AuthRequest.class))).thenReturn(token);

        //When - Then
        mockMvc.perform(MockMvcRequestBuilders.post(LOGIN_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.token").value("jwt_token"));
    }

    @Test
    @DisplayName("Should return 400 on invalid login request")
    void shouldReturnBadRequestOnInvalidLogin() throws Exception {
        //Given
        var invalidRequest = new AuthRequest("", "");

        //When - Then
        mockMvc.perform(MockMvcRequestBuilders.post(LOGIN_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(invalidRequest)))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("Should return 200 and logout message on successful logout")
    void shouldReturnSuccessMessageOnLogout() throws Exception {
        //Given
        when(securityService.logout(anyString())).thenReturn("Successfully logged out");

        //When - Then
        mockMvc.perform(MockMvcRequestBuilders.post(LOGOUT_URL)
                        .header("Authorization", "Bearer "))
                .andExpect(status().isOk())
                .andExpect(MockMvcResultMatchers.content().string("Successfully logged out"));
    }
}