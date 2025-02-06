package com.crm.resources;

import com.crm.exceptions.UserBlockedException;
import com.crm.models.AuthRequest;
import com.crm.models.Token;
import com.crm.services.security.BruteForceService;
import com.crm.services.security.CustomUserDetailsService;
import com.crm.services.security.JwtService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
@Tag(name = "REST API for authentication", description = "Provides resource methods for authentication")
public class AuthController {
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final CustomUserDetailsService userDetailsService;
    private final BruteForceService bruteForceService;

    @Operation(
            summary = "Login for already registered users",
            description = "Creates a token for users.",
            parameters = {
                    @Parameter(name = "request", description = "AuthRequest object", required = true)
            },
            responses = {
                    @ApiResponse(responseCode = "201", description = "Token created"),
                    @ApiResponse(responseCode = "400", description = "Bad request"),
                    @ApiResponse(responseCode = "404", description = "Not found"),
                    @ApiResponse(responseCode = "500", description = "Internal Server Error")
            }
    )
    @PostMapping("/login")
    public ResponseEntity<Token> login(@RequestBody AuthRequest request) {
        if (bruteForceService.isBlocked(request.getUsername())) {
            throw new UserBlockedException("User is temporarily blocked. Try again later.");
        }

        authentication(request);

        bruteForceService.loginSucceeded(request.getUsername());
        var userDetails = userDetailsService.loadUserByUsername(request.getUsername());
        return ResponseEntity.status(HttpStatus.CREATED).body(jwtService.generateToken(userDetails));
    }

    private void authentication(AuthRequest request) {
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword())
            );
        } catch (Exception e) {
            bruteForceService.loginFailed(request.getUsername());
            throw new BadCredentialsException("Invalid credentials");
        }
    }

    @Operation(
            summary = "Logout for already registered users",
            description = "Makes token unavailable for using",
            parameters = {
                    @Parameter(name = "authHeader", description = "Authorization header", required = true)
            },
            responses = {
                    @ApiResponse(responseCode = "200", description = "Token was destroyed"),
                    @ApiResponse(responseCode = "400", description = "Bad request"),
                    @ApiResponse(responseCode = "404", description = "Not found"),
                    @ApiResponse(responseCode = "500", description = "Internal Server Error")
            }
    )
    @PostMapping("/logout")
    public ResponseEntity<String> logout(@RequestHeader("Authorization") String authHeader) {
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            var token = authHeader.substring(7);
            bruteForceService.logout(token);
            return ResponseEntity.ok("Logged out successfully");
        }

        throw new BadCredentialsException("Invalid credentials");
    }
}
