package com.crm.resources;

import com.crm.models.AuthRequest;
import com.crm.models.Token;
import com.crm.services.security.GymSecurityService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
@Tag(name = "REST API for authentication", description = "Provides resource methods for authentication")
public class AuthController {
    private final GymSecurityService securityService;

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
    public ResponseEntity<Token> login(@RequestBody @Valid AuthRequest request) {
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(securityService.login(request));
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
        return ResponseEntity.ok(securityService.logout(authHeader));
    }
}
