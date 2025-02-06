package com.crm.services.security;

import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class BruteForceService {
    private static final int MAX_ATTEMPTS = 3;
    private static final long LOCK_TIME_MS = 5 * 60 * 1000; // 5 min

    private final Map<String, FailedLoginAttempt> attempts = new ConcurrentHashMap<>();
    private final Set<String> blacklistedTokens = ConcurrentHashMap.newKeySet();

    public void loginFailed(String username) {
        var attempt = attempts.getOrDefault(username, new FailedLoginAttempt(0, null));
        attempt.count++;

        if (attempt.count >= MAX_ATTEMPTS) {
            attempt.lockedUntil = Instant.now().plusMillis(LOCK_TIME_MS);
        }
        attempts.put(username, attempt);
    }

    public boolean isBlocked(String username) {
        var attempt = attempts.get(username);
        return attempt != null && attempt.lockedUntil != null && Instant.now().isBefore(attempt.lockedUntil);
    }

    public void loginSucceeded(String username) {
        attempts.remove(username);
    }

    public void logout(String token) {
        blacklistedTokens.add(token);
    }

    public boolean isTokenBlacklisted(String token) {
        return blacklistedTokens.contains(token);
    }

    @AllArgsConstructor
    private static class FailedLoginAttempt {
        private int count;
        private Instant lockedUntil;
    }
}
