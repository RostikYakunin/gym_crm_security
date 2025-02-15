package com.crm.utils;

import com.crm.repositories.entities.Trainee;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.Set;
import java.util.function.Function;

import static org.junit.jupiter.api.Assertions.assertEquals;

class UserUtilsTest {
    private Trainee testUser;

    @BeforeEach
    void setUp() {
        testUser = Trainee.builder()
                .firstName("John")
                .lastName("Doe")
                .id(1L)
                .build();
    }

    @Test
    @DisplayName("generateUniqueUsername should create a unique username without conflicts")
    void generateUniqueUsername_ShouldCreateUniqueUsername_WhenNoConflicts() {
        // Given
        Set<String> existingUsernames = new HashSet<>();
        Function<String, Boolean> usernameExistsChecker = existingUsernames::contains;

        // When
        String result = UserUtils.generateUniqueUsername(testUser, usernameExistsChecker);

        // Then
        assertEquals("John.Doe", result);
    }

    @Test
    @DisplayName("generateUniqueUsername should append counter for conflicting usernames")
    void generateUniqueUsername_ShouldAppendCounter_WhenConflictsExist() {
        // Given
        Set<String> existingUsernames = Set.of("John.Doe");
        Function<String, Boolean> usernameExistsChecker = existingUsernames::contains;

        // When
        String result = UserUtils.generateUniqueUsername(testUser, usernameExistsChecker);

        // Then
        assertEquals("John.Doe1", result);
    }

    @Test
    @DisplayName("generateUniqueUsername should handle multiple conflicts correctly")
    void generateUniqueUsername_ShouldHandleMultipleConflicts() {
        // Given
        Set<String> existingUsernames = Set.of("John.Doe", "John.Doe1", "John.Doe2");
        Function<String, Boolean> usernameExistsChecker = existingUsernames::contains;

        // When
        String result = UserUtils.generateUniqueUsername(testUser, usernameExistsChecker);

        // Then
        assertEquals("John.Doe3", result);
    }
}