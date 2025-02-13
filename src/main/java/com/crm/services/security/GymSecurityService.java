package com.crm.services.security;

import com.crm.exceptions.UserBlockedException;
import com.crm.models.AuthRequest;
import com.crm.models.Token;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.stereotype.Service;

import java.util.Optional;

/**
 * Service responsible for handling authentication and security operations.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class GymSecurityService {
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final CustomUserDetailsService userDetailsService;
    private final BruteForceService bruteForceService;

    /**
     * Authenticates a user and generates a JWT token if successful.
     *
     * @param request The authentication request containing username and password.
     * @return A Token object containing JWT and metadata.
     * @throws UserBlockedException    If the user is temporarily blocked due to multiple failed login attempts.
     * @throws BadCredentialsException If the credentials are invalid.
     */
    public Token login(AuthRequest request) {
        log.info("Starting logging in...");
        if (bruteForceService.isUserBlocked(request.getUsername())) {
            log.info("User is temporarily blocked!");
            throw new UserBlockedException("User is temporarily blocked. Try again later.");
        }

        authentication(request);

        var userDetails = userDetailsService.loadUserByUsername(request.getUsername());
        return jwtService.generateToken(userDetails);
    }

    private void authentication(AuthRequest request) {
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword())
            );
            bruteForceService.loginSucceeded(request.getUsername());
        } catch (Exception e) {
            bruteForceService.loginFailed(request.getUsername());
            throw new BadCredentialsException("Invalid credentials");
        }
    }

    /**
     * Logs out the user by invalidating the provided JWT token.
     *
     * @param authHeader The authorization header containing the JWT token.
     * @return A confirmation message if logout is successful.
     * @throws BadCredentialsException If the token is invalid or missing.
     */
    public String logout(String authHeader) {
        log.info("Starting logging out...");
        return Optional.ofNullable(authHeader)
                .filter(header -> header.startsWith("Bearer "))
                .map(header -> {
                    var token = header.substring(7);
                    bruteForceService.logout(token);
                    return "Successfully logged out ";
                })
                .orElseThrow(
                        () -> {
                            log.error("Inputted data is not valid!");
                            return new BadCredentialsException("Invalid credentials");
                        }
                );
    }
}
