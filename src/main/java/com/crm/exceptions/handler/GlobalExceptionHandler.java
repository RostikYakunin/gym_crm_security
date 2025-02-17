package com.crm.exceptions.handler;

import com.crm.exceptions.PasswordNotMatchException;
import com.crm.exceptions.UserBlockedException;
import com.crm.exceptions.UserNameChangedException;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.security.SignatureException;
import jakarta.persistence.EntityNotFoundException;
import jakarta.validation.ConstraintViolationException;
import lombok.extern.slf4j.Slf4j;
import org.apache.coyote.BadRequestException;
import org.postgresql.util.PSQLException;
import org.slf4j.MDC;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingRequestHeaderException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.nio.file.AccessDeniedException;
import java.util.HashMap;
import java.util.Map;

@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {
    @ExceptionHandler(Exception.class)
    public ResponseEntity<String> handleException(Exception ex) {
        var transactionId = MDC.get("transactionId");

        log.error("[{}] Unexpected error: {}", transactionId, ex.getMessage(), ex);
        return ResponseEntity.internalServerError()
                .body("An unexpected error occurred. Please contact support.\n" + ex.getCause());
    }

    @ExceptionHandler(EntityNotFoundException.class)
    public ResponseEntity<String> handleEntityNotFoundException(EntityNotFoundException ex) {
        var transactionId = MDC.get("transactionId");
        log.warn("[{}] Entity not found: {}", transactionId, ex.getMessage());

        return ResponseEntity.ok()
                .body(ex.getMessage());
    }

    @ExceptionHandler(BadRequestException.class)
    public ResponseEntity<String> handleBadRequestException(BadRequestException ex) {
        var transactionId = MDC.get("transactionId");
        log.warn("[{}] Bad request: {}", transactionId, ex.getMessage());
        return ResponseEntity.badRequest()
                .body(ex.getMessage());
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Map<String, String>> handleMethodArgumentNotValidException(MethodArgumentNotValidException ex) {
        var transactionId = MDC.get("transactionId");
        var errors = new HashMap<String, String>();
        ex.getBindingResult()
                .getFieldErrors()
                .forEach(
                        error -> errors.put(error.getField(), error.getDefaultMessage())
                );

        log.warn("[{}] Validation error: {}", transactionId, errors);
        return ResponseEntity.badRequest()
                .body(errors);
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<String> handleInvalidRequestBody(HttpMessageNotReadableException ex) {
        var transactionId = MDC.get("transactionId");

        log.warn("[{}] Malformed request body: {}", transactionId, ex.getMessage());
        return ResponseEntity.badRequest()
                .body("Invalid request body: " + ex.getMessage());
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<String> handleAccessDeniedException(AccessDeniedException ex) {
        var transactionId = MDC.get("transactionId");

        log.warn("[{}] Access denied: {}", transactionId, ex.getMessage());
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body("Access denied: " + ex.getMessage());
    }

    @ExceptionHandler(IllegalStateException.class)
    public ResponseEntity<String> handleIllegalStateException(IllegalStateException ex) {
        var transactionId = MDC.get("transactionId");

        log.warn("[{}] Registration conflict: {}", transactionId, ex.getMessage());
        return ResponseEntity.badRequest()
                .body(ex.getMessage());
    }

    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    public ResponseEntity<String> handleHttpRequestMethodNotSupportedException(HttpRequestMethodNotSupportedException ex) {
        var transactionId = MDC.get("transactionId");

        log.warn("[{}] This request with these parameters is not supported: {}", transactionId, ex.getMessage());
        return ResponseEntity.badRequest()
                .body(ex.getMessage());
    }

    @ExceptionHandler(MissingServletRequestParameterException.class)
    public ResponseEntity<String> handleMissingServletRequestParameterException(MissingServletRequestParameterException ex) {
        var transactionId = MDC.get("transactionId");

        log.warn("[{}] Parameters are not correct for this request: {}", transactionId, ex.getMessage());
        return ResponseEntity.badRequest()
                .body(ex.getMessage());
    }

    @ExceptionHandler(PSQLException.class)
    public ResponseEntity<String> handlePSQLException(PSQLException ex) {
        var transactionId = MDC.get("transactionId");

        log.warn("[{}] Something went wrong with SQL request: {}", transactionId, ex.getMessage());
        return ResponseEntity.badRequest()
                .body("Your request is wrong, please pay attention on your request details");
    }

    @ExceptionHandler(PasswordNotMatchException.class)
    public ResponseEntity<String> handlePasswordNotMatchException(PasswordNotMatchException ex) {
        var transactionId = MDC.get("transactionId");

        log.warn("[{}] Password was not changed: inputted password is wrong: {}", transactionId, ex.getMessage());
        return ResponseEntity.badRequest()
                .body("Password was not changed:" + ex.getMessage());
    }

    @ExceptionHandler(UserNameChangedException.class)
    public ResponseEntity<String> handleUserNameChangedException(UserNameChangedException ex) {
        var transactionId = MDC.get("transactionId");

        log.warn("[{}] User name can not be changed: {}", transactionId, ex.getMessage());
        return ResponseEntity.badRequest()
                .body("User name was changed:" + ex.getMessage());
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<String> handleIllegalArgumentException(IllegalArgumentException ex) {
        var transactionId = MDC.get("transactionId");

        log.warn("[{}] Arguments are wrong: {}", transactionId, ex.getMessage());
        return ResponseEntity.badRequest()
                .body("Arguments are wrong:" + ex.getMessage());
    }

    @ExceptionHandler(ConstraintViolationException.class)
    public ResponseEntity<String> handleConstraintViolationException(ConstraintViolationException ex) {
        var transactionId = MDC.get("transactionId");

        log.warn("[{}] Filed statement execution: {}", transactionId, ex.getMessage());
        return ResponseEntity.badRequest()
                .body("Arguments are wrong, please pay attention and try again inputting valid data");
    }

    @ExceptionHandler(ExpiredJwtException.class)
    public ResponseEntity<String> handleExpiredJwtException(ExpiredJwtException ex) {
        var transactionId = MDC.get("transactionId");

        log.warn("[{}] JWT expired: {}", transactionId, ex.getMessage());
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body("JWT token has expired: " + ex.getMessage());
    }

    @ExceptionHandler(SignatureException.class)
    public ResponseEntity<String> handleSignatureException(SignatureException ex) {
        var transactionId = MDC.get("transactionId");

        log.warn("[{}] Invalid JWT signature: {}", transactionId, ex.getMessage());
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body("Invalid JWT signature: " + ex.getMessage());
    }

    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<String> handleJwtTokenMissingException(BadCredentialsException ex) {
        var transactionId = MDC.get("transactionId");

        log.warn("[{}] Bad credentials: {}", transactionId, ex.getMessage());
        return ResponseEntity.badRequest()
                .body("Authentication failed, please check your inputted data!");
    }

    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<String> handleAuthenticationException(AuthenticationException ex) {
        var transactionId = MDC.get("transactionId");

        log.warn("[{}] Authentication failed: {}", transactionId, ex.getMessage());
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body("Authentication failed: " + ex.getMessage());
    }

    @ExceptionHandler(UserBlockedException.class)
    public ResponseEntity<String> handleAuthenticationException(UserBlockedException ex) {
        var transactionId = MDC.get("transactionId");

        log.warn("[{}] User is temporary blocked: {}", transactionId, ex.getMessage());
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body("Authentication failed:" + ex.getMessage());
    }

    @ExceptionHandler(MissingRequestHeaderException.class)
    public ResponseEntity<String> handleAuthenticationException(MissingRequestHeaderException ex) {
        var transactionId = MDC.get("transactionId");

        log.warn("[{}] Required request header 'Authorization': {}", transactionId, ex.getMessage());
        return ResponseEntity.badRequest()
                .body("Required request header 'Authorization'");
    }
}
