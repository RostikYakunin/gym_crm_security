package com.crm.services.security;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

@Service
@Slf4j
public class BruteForceService {
    @Value("${spring.security.brute-force.attempts}")
    private int maxAttempts;
    @Value("${spring.security.brute-force.locked_time_minutes}")
    private long lockedTime;
    private final Map<String, FailedLoginAttempt> attempts = new ConcurrentHashMap<>();
    private final Set<String> blacklistedTokens = ConcurrentHashMap.newKeySet();

    public void loginFailed(String username) {
        log.info("Saving failed login`s attempt...");
        var attempt = attempts.getOrDefault(username, new FailedLoginAttempt(0, null));
        attempt.count++;

        if (attempt.count >= maxAttempts) {
            log.info("User with username:" + username + " has 3 failed login`s attempt and was blocked");
            attempt.lockedUntil = Instant.now().plusMillis(lockedTime * 60_000);
            return;
        }

        attempts.put(username, attempt);
    }

    public boolean isUserBlocked(String username) {
        log.info("Verifying if user is blocked...");
        var attempt = attempts.get(username);
        return attempt != null && attempt.lockedUntil != null && Instant.now().isBefore(attempt.lockedUntil);
    }

    public void loginSucceeded(String username) {
        log.info("Login was successful, all unsuccessful attempts were deleted...");
        attempts.remove(username);
    }

    public void logout(String token) {
        log.info("Token was blacklisted and not available now!");
        blacklistedTokens.add(token);
    }

    public boolean isTokenBlacklisted(String token) {
        log.info("Verifying is token blocked...");
        return blacklistedTokens.contains(token);
    }

    @AllArgsConstructor
    private static class FailedLoginAttempt {
        private int count;
        private Instant lockedUntil;
    }
}
