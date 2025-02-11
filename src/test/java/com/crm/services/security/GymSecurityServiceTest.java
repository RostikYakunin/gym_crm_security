package com.crm.services.security;

import com.crm.UnitTestBase;
import com.crm.exceptions.UserBlockedException;
import com.crm.models.AuthRequest;
import com.crm.models.Token;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class GymSecurityServiceTest extends UnitTestBase {
    @Mock
    private AuthenticationManager authenticationManager;
    @Mock
    private JwtService jwtService;
    @Mock
    private CustomUserDetailsService userDetailsService;
    @Mock
    private BruteForceService bruteForceService;
    @InjectMocks
    private GymSecurityService gymSecurityService;
    private AuthRequest authRequest;
    private UserDetails userDetails;

    @BeforeEach
    void setUp() {
        authRequest = new AuthRequest("testUser", "Password1");
        userDetails = mock(UserDetails.class);
    }

    @Test
    @DisplayName("Should successfully login")
    void login_Successful() {
        //Given
        when(bruteForceService.isUserBlocked(authRequest.getUsername())).thenReturn(false);
        when(userDetailsService.loadUserByUsername(authRequest.getUsername())).thenReturn(userDetails);
        when(jwtService.generateToken(userDetails)).thenReturn(new Token("testUser", new Date(), new Date(), "jwt-token"));

        //When
        var token = gymSecurityService.login(authRequest);

        //Then
        assertNotNull(token);
        assertEquals("testUser", token.getOwnerUserName());
        verify(authenticationManager).authenticate(any(UsernamePasswordAuthenticationToken.class));
    }

    @Test
    @DisplayName("Should throw exception when user is blocked")
    void login_UserBlocked_ShouldThrowException() {
        //Given
        when(bruteForceService.isUserBlocked(authRequest.getUsername())).thenReturn(true);

        //When - Then
        assertThrows(
                UserBlockedException.class,
                () -> gymSecurityService.login(authRequest)
        );
    }

    @Test
    @DisplayName("Should throw exception when user inputted wrong info")
    void login_InvalidCredentials_ShouldThrowException() {
        //Given
        when(bruteForceService.isUserBlocked(authRequest.getUsername())).thenReturn(false);
        doThrow(new BadCredentialsException("Invalid credentials"))
                .when(authenticationManager)
                .authenticate(any(UsernamePasswordAuthenticationToken.class));

        //When - Then
        assertThrows(
                BadCredentialsException.class,
                () -> gymSecurityService.login(authRequest)
        );
    }

    @Test
    @DisplayName("Should do successful logout when token is valid")
    void logout_ValidToken_ShouldReturnSuccessMessage() {
        //Given
        var authHeader = "Bearer validToken";
        doNothing().when(bruteForceService).logout("validToken");

        //When
        var result = gymSecurityService.logout(authHeader);

        //Then
        assertEquals("Successfully logged out ", result);
    }

    @Test
    @DisplayName("Should throw exception when invalid token")
    void logout_InvalidToken_ShouldThrowException() {
        //Given
        var authHeader = "InvalidToken";

        //When - Then
        assertThrows(BadCredentialsException.class, () -> gymSecurityService.logout(authHeader));
    }
}