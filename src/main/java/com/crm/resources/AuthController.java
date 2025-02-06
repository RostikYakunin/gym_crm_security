package com.crm.resources;

import com.crm.dtos.AuthRequest;
import com.crm.exceptions.UserBlockedException;
import com.crm.models.Token;
import com.crm.services.security.BruteForceService;
import com.crm.services.security.CustomUserDetailsService;
import com.crm.services.security.JwtService;
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
public class AuthController {
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final CustomUserDetailsService userDetailsService;
    private final BruteForceService bruteForceService;

    @PostMapping("/login")
    public ResponseEntity<Token> login(@RequestBody AuthRequest request) {
        if (bruteForceService.isBlocked(request.getUsername())) {
            throw new UserBlockedException("User is temporarily blocked. Try again later.");
        }

        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword())
            );
        } catch (Exception e) {
            bruteForceService.loginFailed(request.getUsername());
            throw new BadCredentialsException("Invalid credentials");
        }

        bruteForceService.loginSucceeded(request.getUsername());
        var userDetails = userDetailsService.loadUserByUsername(request.getUsername());
        return ResponseEntity.status(HttpStatus.CREATED).body(jwtService.generateToken(userDetails));
    }

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
