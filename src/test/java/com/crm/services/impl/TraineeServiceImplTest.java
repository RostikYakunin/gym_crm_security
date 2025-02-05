package com.crm.services.impl;

import com.crm.UnitTestBase;
import com.crm.dtos.UserLoginDto;
import com.crm.dtos.trainee.TraineeDto;
import com.crm.dtos.trainee.TraineeTrainingUpdateDto;
import com.crm.dtos.trainee.TraineeView;
import com.crm.dtos.training.TrainingDto;
import com.crm.dtos.training.TrainingView;
import com.crm.enums.TrainingType;
import com.crm.exceptions.PasswordNotMatchException;
import com.crm.exceptions.UserNameChangedException;
import com.crm.repositories.TraineeRepo;
import com.crm.repositories.entities.Trainee;
import com.crm.repositories.entities.Training;
import com.crm.utils.UserUtils;
import jakarta.persistence.EntityNotFoundException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.springframework.core.convert.ConversionService;

import java.time.LocalDate;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class TraineeServiceImplTest extends UnitTestBase {
    @Mock
    private TraineeRepo traineeRepo;
    @Mock
    private ConversionService conversionService;

    @Captor
    private ArgumentCaptor<String> stringArgumentCaptor;

    @InjectMocks
    private TraineeServiceImpl traineeService;

    @Test
    @DisplayName("findById should return trainee when exists")
    void findById_ShouldReturnTrainee_WhenExists() {
        // Given
        when(traineeRepo.findById(anyLong())).thenReturn(Optional.of(testTrainee));

        // When
        var result = traineeService.findById(1);

        // Then
        assertEquals(testTrainee, result);
        verify(traineeRepo, times(1)).findById(idArgumentCaptor.capture());
    }

    @Test
    @DisplayName("save - should save trainee using parameters")
    void save_ShouldSaveTraineeUsingParameters() {
        // Given
        var expectedUserName = "testName.testLastName";

        when(traineeRepo.save(any(Trainee.class))).thenReturn(testTrainee);

        // When
        var result = traineeService.save("John", "Doe", "password", "testAddress", LocalDate.of(1998, 11, 11));

        // Then
        assertEquals(expectedUserName, result.getUserName());
        assertNotNull(result.getPassword());
        assertEquals(result, result);

        verify(traineeRepo, times(1)).save(traineeArgumentCaptor.capture());
    }

    @Test
    @DisplayName("save - should generate username and password, then save trainee")
    void save_ShouldGenerateUsernameAndPasswordAndSaveTrainee() {
        // Given
        var expectedUserName = "testName.testLastName";

        when(traineeRepo.save(any(Trainee.class))).thenReturn(testTrainee);

        // When
        var result = traineeService.save(testTrainee);

        // Then
        assertEquals(expectedUserName, result.getUserName());
        assertNotNull(result.getPassword());
        assertEquals(result, result);

        verify(traineeRepo, times(1)).save(traineeArgumentCaptor.capture());
    }

    @Test
    @DisplayName("deleteById should return true when trainee was successfully deleted")
    void deleteById_ShouldDelete_WhenTraineeExists() {
        // Given
        doNothing().when(traineeRepo).delete(any(Trainee.class));

        // When
        traineeService.delete(testTrainee);

        // Then
        verify(traineeRepo, times(1)).delete(traineeArgumentCaptor.capture());
    }

    @Test
    @DisplayName("update should return updated trainee when trainee exists")
    void update_ShouldReturnUpdatedTrainee_WhenTraineeExists() {
        // Given
        when(traineeRepo.save(any(Trainee.class))).thenReturn(testTrainee);

        // When
        var result = traineeService.update(testTrainee);

        // Then
        assertNotNull(result);
        assertEquals(testTrainee, result);

        verify(traineeRepo, times(1)).save(traineeArgumentCaptor.capture());
    }

    @Test
    @DisplayName("deleteByUserName - should delete entity when trainee was found in DB")
    void deleteByUserName_ShouldDeleteEntity_WhenTraineeWasFound() {
        // Given
        when(traineeRepo.findByUserName(anyString())).thenReturn(Optional.of(testTrainee));
        doNothing().when(traineeRepo).delete(any(Trainee.class));

        // When
        traineeService.deleteByUsername(testTrainee.getUserName());

        // Then
        verify(traineeRepo, times(1)).findByUserName(stringArgumentCaptor.capture());
        verify(traineeRepo, times(1)).delete(traineeArgumentCaptor.capture());
    }

    @Test
    @DisplayName("findByUsername - should find entity when trainee was found in DB")
    void findByUsername_ShouldFindEntity_WhenTraineeWasFound() {
        // Given
        when(traineeRepo.findByUserName(anyString()))
                .thenReturn(Optional.of(testTrainee))
                .thenReturn(Optional.empty());

        // When
        var result1 = traineeService.findByUsername(testTrainee.getUserName());
        var result2 = traineeService.findByUsername(testTrainee.getUserName());

        // Then
        assertNotNull(result1);
        assertEquals(testTrainee, result1);
        assertNull(result2);

        verify(traineeRepo, times(2)).findByUserName(stringArgumentCaptor.capture());
    }

    @Test
    @DisplayName("changePassword - should change password when trainee`s password matches with found in DB")
    void changePassword_ShouldChangePass_WhenPasswordsMatches() {
        // Given
        when(traineeRepo.findByUserName(anyString())).thenReturn(Optional.of(testTrainee));
        when(traineeRepo.save(any(Trainee.class))).thenReturn(testTrainee);
        testTrainee.setPassword(UserUtils.hashPassword(testTrainee.getPassword()));

        // When - Then
        assertThrows(
                PasswordNotMatchException.class,
                () -> traineeService.changePassword(
                        new UserLoginDto(testTrainee.getUserName(), "wrongPass", "newPass")
                )
        );

        assertDoesNotThrow(
                () -> traineeService.changePassword(
                        new UserLoginDto(testTrainee.getUserName(), "testPassword", "newPass")
                )
        );

        verify(traineeRepo, times(1)).save(traineeArgumentCaptor.capture());
    }

    @Test
    @DisplayName("Toggle active status - should deactivate when currently active")
    void toggleActiveStatus_ShouldDeactivateWhenCurrentlyActive() {
        // Given
        when(traineeRepo.findById(anyLong())).thenReturn(Optional.of(testTrainee));
        when(traineeRepo.save(any(Trainee.class))).thenReturn(testTrainee);

        // When
        var result1 = traineeService.activateStatus(1L);
        var result2 = traineeService.deactivateStatus(1L);

        // Then
        Assertions.assertTrue(result1);
        Assertions.assertFalse(result2);

        verify(traineeRepo, times(2)).findById(1L);
        verify(traineeRepo, times(2)).save(traineeArgumentCaptor.capture());
    }

    @Test
    @DisplayName("Is username and password matching - should return true for matching credentials")
    void isUsernameAndPasswordMatching_ShouldReturnTrueForMatchingCredentials() {
        // Given
        testTrainee.setPassword(UserUtils.hashPassword(testTrainee.getPassword()));
        when(traineeRepo.findByUserName(anyString()))
                .thenReturn(Optional.of(testTrainee))
                .thenReturn(Optional.of(testTrainee))
                .thenReturn(Optional.empty());

        // When
        var result1 = traineeService.isUsernameAndPasswordMatching("testName.testLastName", "testPassword");
        var result2 = traineeService.isUsernameAndPasswordMatching("testName.testLastName", "wrongPassword");
        var result3 = traineeService.isUsernameAndPasswordMatching("unknownUser", "testPassword");

        // Then
        Assertions.assertTrue(result1);
        Assertions.assertFalse(result2);
        Assertions.assertFalse(result3);
        verify(traineeRepo, times(3)).findByUserName(stringArgumentCaptor.capture());
    }

    @Test
    @DisplayName("Should find user by user name and nothing was thrown")
    void findByUsernameOrThrow_ShouldReturnEntity_WhenUserExists() {
        // Given
        when(traineeRepo.findByUserName(anyString())).thenReturn(Optional.of(testTrainee));

        // When

        var actualUser = assertDoesNotThrow(
                () -> traineeService.findByUsernameOrThrow(testTrainee.getUserName())
        );

        // Then
        assertNotNull(actualUser);
        assertEquals(testTrainee, actualUser);
        verify(traineeRepo, times(1)).findByUserName(stringArgumentCaptor.capture());
    }

    @Test
    @DisplayName("Should throw EntityNotFoundException when nothing was found")
    void findByUsernameOrThrow_ShouldThrowException_WhenUserNotFound() {
        // Given
        when(traineeRepo.findByUserName(anyString())).thenReturn(Optional.empty());

        // When - Then
        assertThrows(
                EntityNotFoundException.class,
                () -> traineeService.findByUsernameOrThrow("username"),
                "Entity with username username not found"
        );

        verify(traineeRepo, times(1)).findByUserName(stringArgumentCaptor.capture());
    }

    @ParameterizedTest
    @CsvSource({
            "trainee1, trainer1, YOGA, 1",
            "trainee2, trainer2, YOGA, 0"
    })
    @DisplayName("Should return/not return list of trainings")
    void findTraineeTrainingsByCriteria_ShouldReturnCorrectData(String traineeUsername, String trainerUsername, TrainingType trainingType, int expectedSize) {
        // Given
        var fromDate = LocalDate.of(2024, 1, 1);
        var toDate = LocalDate.of(2024, 12, 31);
        List<Training> expectedTrainings = expectedSize > 0 ? List.of(mock(Training.class)) : Collections.emptyList();

        lenient().when(conversionService.convert(any(Training.class), eq(TrainingView.class))).thenReturn(new TrainingView());
        when(traineeRepo.getTraineeTrainingsByCriteria(traineeUsername, fromDate, toDate, trainerUsername, trainingType))
                .thenReturn(expectedTrainings);

        // When
        var actualTrainings = traineeService.findTraineeTrainingsByCriteria(traineeUsername, fromDate, toDate, trainerUsername, trainingType);

        // Then
        assertNotNull(actualTrainings);
        assertEquals(expectedSize, actualTrainings.size());
        verify(traineeRepo, times(1)).getTraineeTrainingsByCriteria(traineeUsername, fromDate, toDate, trainerUsername, trainingType);
    }

    @Test
    @DisplayName("addTrainee - should save trainee and return it")
    void addTrainee_ShouldSave_AndReturnIt() {
        // Given
        when(conversionService.convert(any(TraineeDto.class), eq(Trainee.class))).thenReturn(testTrainee);
        when(traineeRepo.save(any(Trainee.class))).thenReturn(testTrainee);
        when(conversionService.convert(any(Trainee.class), eq(TraineeDto.class))).thenReturn(testTraineeDto);

        // When
        var result = traineeService.addTrainee(testTraineeDto);

        // Then
        assertEquals(testTrainee.getUserName(), result.getUserName());
        verify(traineeRepo, times(1)).save(traineeArgumentCaptor.capture());
    }

    @Test
    @DisplayName("findProfileByUserName - should find trainee and return it")
    void findProfileByUserName_ShouldFind_AndReturnIt() {
        // Given
        when(traineeRepo.findByUserName(anyString())).thenReturn(Optional.ofNullable(testTrainee));
        when(conversionService.convert(any(Trainee.class), eq(TraineeView.class))).thenReturn(new TraineeView());

        // When
        var result = traineeService.findProfileByUserName(testTraineeDto.getUserName());

        // Then
        assertNotNull(result);
        verify(traineeRepo, times(1)).findByUserName(stringArgumentCaptor.capture());
    }

    @Test
    @DisplayName("updateTraineeProfile - should update trainee`s profile and return it")
    void updateTraineeProfile_shouldUpdateTrainee_ThenReturnIt() {
        // Given
        when(traineeRepo.findByUserName(anyString())).thenReturn(Optional.ofNullable(testTrainee));
        when(traineeRepo.save(any(Trainee.class))).thenReturn(testTrainee);
        when(conversionService.convert(any(TraineeDto.class), eq(Trainee.class))).thenReturn(testTrainee);
        when(conversionService.convert(any(Trainee.class), eq(TraineeView.class))).thenReturn(new TraineeView());

        // When
        var result = traineeService.updateTraineeProfile(1L, testTraineeDto);

        // Then
        assertNotNull(result);
        verify(traineeRepo, times(1)).findByUserName(stringArgumentCaptor.capture());
    }

    @Test
    @DisplayName("updateTraineeProfile - should throw Exception")
    void updateTraineeProfile_shouldThrowException() {
        // Given
        when(traineeRepo.findByUserName(anyString())).thenReturn(Optional.ofNullable(testTrainee));
        testTraineeDto.setUserName("WrongUsername");

        // When - Then
        assertThrows(
                UserNameChangedException.class,
                () -> traineeService.updateTraineeProfile(1L, testTraineeDto),
                "User name changing is forbidden!"
        );

        verify(traineeRepo, times(1)).findByUserName(stringArgumentCaptor.capture());
    }

    @Test
    @DisplayName("updateTraineeTrainings - should update trainee`s trainings and return set ")
    void updateTraineeTrainings_shouldUpdateTrainee_ThenReturnSet() {
        // Given
        when(conversionService.convert(any(TrainingDto.class), eq(Training.class))).thenReturn(testTraining);
        when(traineeRepo.findByUserName(anyString())).thenReturn(Optional.ofNullable(testTrainee));
        when(traineeRepo.save(any(Trainee.class))).thenReturn(testTrainee);
        when(conversionService.convert(any(Training.class), eq(TrainingView.class))).thenReturn(new TrainingView());

        var testDto = TraineeTrainingUpdateDto.builder()
                .userName(testTrainee.getUserName())
                .trainings(List.of(new TrainingDto()))
                .build();

        // When
        var result = traineeService.updateTraineeTrainings(testDto);

        // Then
        assertFalse(result.isEmpty());
        verify(traineeRepo, times(1)).findByUserName(stringArgumentCaptor.capture());
        verify(traineeRepo, times(1)).save(traineeArgumentCaptor.capture());
    }

    @Test
    @DisplayName("updateTraineeTrainings - should throw IllegalArgumentException")
    void updateTraineeTrainings_shouldThrowException() {
        // Given
        when(conversionService.convert(any(TrainingDto.class), eq(Training.class))).thenReturn(testTraining);
        when(traineeRepo.findByUserName(anyString())).thenReturn(Optional.ofNullable(Trainee.builder().id(2L).build()));

        var testDto = TraineeTrainingUpdateDto.builder()
                .userName(testTrainee.getUserName())
                .trainings(List.of(new TrainingDto()))
                .build();

        // When - Then
        assertThrows(
                IllegalArgumentException.class,
                () -> traineeService.updateTraineeTrainings(testDto),
                "Inputted trainings are not belong to user with id=1"
        );

        verify(traineeRepo, times(1)).findByUserName(stringArgumentCaptor.capture());
        verify(traineeRepo, never()).save(traineeArgumentCaptor.capture());
    }
}