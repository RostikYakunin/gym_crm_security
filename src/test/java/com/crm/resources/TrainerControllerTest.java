package com.crm.resources;

import com.crm.UnitTestBase;
import com.crm.dtos.UserLoginDto;
import com.crm.dtos.UserStatusUpdateDto;
import com.crm.dtos.trainer.TrainerDto;
import com.crm.dtos.trainer.TrainerView;
import com.crm.dtos.training.TrainingView;
import com.crm.enums.TrainingType;
import com.crm.init.DataInitializer;
import com.crm.repositories.entities.Trainer;
import com.crm.services.TrainerService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.time.LocalDate;
import java.util.Set;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@ActiveProfiles("test")
@AutoConfigureMockMvc
class TrainerControllerTest extends UnitTestBase {
    @Autowired
    private MockMvc mockMvc;
    @MockitoBean
    private TrainerService trainerService;
    @MockitoBean
    private DataInitializer dataInitializer;
    @Autowired
    private ObjectMapper objectMapper;

    @ParameterizedTest
    @CsvSource({
            "John, Doe, Passw123, YOGA",
            "'', Doe, Passw123, YOGA",
            "John, '', Passw123, YOGA",
            "John, Doe, '', YOGA",
            "John, Doe, password123, ''"
    })
    @DisplayName("Should create/not create trainer according to data")
    void registerTrainer_ShouldHandleVariousInputs(
            String firstName, String lastName, String password, String trainingType
    ) throws Exception {
        // Given
        var trainerDto = new TrainerDto();
        trainerDto.setFirstName(firstName);
        trainerDto.setLastName(lastName);
        trainerDto.setPassword(password);
        trainerDto.setSpecialization(trainingType.isEmpty() ? null : TrainingType.valueOf(trainingType));

        var trainer = new Trainer();

        if (!firstName.isEmpty() && !lastName.isEmpty() && !password.isEmpty() && !trainingType.isEmpty()) {
            when(trainerService.save(any(Trainer.class))).thenReturn(trainer);

            //When - Then
            mockMvc.perform(post("/api/v1/trainer")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(trainerDto)))
                    .andExpect(status().isCreated());
        } else {
            mockMvc.perform(post("/api/v1/trainer")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(trainerDto)))
                    .andExpect(status().isBadRequest());
        }
    }

    @ParameterizedTest
    @CsvSource({
            "user1, oldPass123, newPass123",
            "'', oldPass123, newPass123",
            "user1, '', newPass123",
            "user1, oldPass123, ''"
    })
    @DisplayName("Should change/not change trainer`s password according to data")
    void changePassword_ShouldHandleVariousInputs(
            String userName, String oldPassword, String newPassword
    ) throws Exception {
        // Given
        UserLoginDto loginDto = new UserLoginDto();
        loginDto.setUserName(userName);
        loginDto.setOldPassword(oldPassword);
        loginDto.setNewPassword(newPassword);

        Trainer trainer = new Trainer();

        if (!userName.isEmpty() && !oldPassword.isEmpty() && !newPassword.isEmpty()) {
            when(trainerService.findByUsernameOrThrow(userName)).thenReturn(trainer);
            doNothing().when(trainerService).changePassword(any(UserLoginDto.class));

            // When - Then
            mockMvc.perform(put("/api/v1/trainer/password")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(loginDto)))
                    .andExpect(status().isOk())
                    .andExpect(content().string("Password successfully changed"));
        } else {
            mockMvc.perform(put("/api/v1/trainer/password")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(loginDto)))
                    .andExpect(status().isBadRequest());
        }
    }

    @ParameterizedTest
    @CsvSource({
            "user1"
    })
    @DisplayName("Should get/not get trainer`s profile according to data")
    void getTrainerProfile_ShouldHandleVariousInputs(String username) throws Exception {
        // Given
        var trainerView = TrainerView.builder()
                .firstName("TestName")
                .build();

        when(trainerService.findProfileByUserName(username)).thenReturn(trainerView);

        //When - Then
        mockMvc.perform(get("/api/v1/trainer/{username}", username)
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.firstName").value(trainerView.getFirstName()));
    }

    @ParameterizedTest
    @CsvSource({
            "John, Doe, user1, YOGA, true",
            "'', Doe, user1, YOGA, true",
            "John, '', user1, YOGA, true",
            "John, Doe, user1, '', true",
    })
    @DisplayName("Should update/not update trainer`s profile according to data")
    void updateTrainer_ShouldHandleVariousInputs(
            String firstName, String lastName, String userName, String specialization, String isActive
    ) throws Exception {
        // Given
        var updateDto = TrainerDto.builder()
                .firstName(firstName)
                .lastName(lastName)
                .userName(userName)
                .password("Pass234")
                .specialization(specialization.isEmpty() ? null : TrainingType.valueOf(specialization))
                .isActive(isActive.isEmpty() ? null : Boolean.parseBoolean(isActive))
                .build();

        var trainer = Trainer.builder().userName(userName).build();
        var trainerView = new TrainerView();

        if (!firstName.isEmpty() && !lastName.isEmpty() && !userName.isEmpty() && !specialization.isEmpty() && !isActive.isEmpty()) {
            when(trainerService.findById(anyLong())).thenReturn(trainer);
            when(trainerService.update(any(Trainer.class))).thenReturn(trainer);

            // When - Then
            mockMvc.perform(put("/api/v1/trainer/1")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(updateDto)))
                    .andExpect(status().isOk());
        } else {
            mockMvc.perform(put("/api/v1/trainer/1")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(updateDto)))
                    .andExpect(status().isBadRequest());
        }
    }

    @ParameterizedTest
    @CsvSource({
            "user1, John, Doe, john.doe, YOGA",
            "user2, Jane, Doe, jane.doe, YOGA"
    })
    @DisplayName("Should get not assigned trainers according to data")
    void getNotAssignedTrainers_ShouldReturnTrainers(
            String username, String firstName, String lastName, String trainerUsername, TrainingType specialization
    ) throws Exception {
        //Given
        var expectedTrainer = TrainerDto.builder()
                .firstName(firstName)
                .lastName(lastName)
                .userName(trainerUsername)
                .specialization(specialization)
                .isActive(true)
                .build();
        when(trainerService.findNotAssignedTrainersByTraineeUserName(anyString())).thenReturn(Set.of(expectedTrainer));

        //When - Then
        mockMvc.perform(get("/api/v1/trainer/unassigned/{username}", username))
                .andExpect(status().isOk())
                .andDo(print())
                .andExpect(jsonPath("$[0].firstName").value(firstName))
                .andExpect(jsonPath("$[0].lastName").value(lastName))
                .andExpect(jsonPath("$[0].userName").value(trainerUsername))
                .andExpect(jsonPath("$[0].specialization").value(specialization.name()));
    }

    @ParameterizedTest
    @CsvSource({
            "john.doe, true, 'Trainer with userName=john.doe was activated.'",
            "jane.doe, false, 'Trainer with userName=jane.doe was deactivated.'"
    })
    @DisplayName("Should update trainee`s status according to data")
    void updateTraineeStatus_ShouldUpdateStatus(
            String userName, boolean isActive, String expectedMessage
    ) throws Exception {
        //Given
        var statusUpdateDto = new UserStatusUpdateDto(userName, isActive);
        testTrainer.setUserName(userName);

        when(trainerService.findByUsernameOrThrow(anyString())).thenReturn(testTrainer);
        lenient().when(trainerService.activateStatus(anyLong())).thenReturn(true);
        lenient().when(trainerService.deactivateStatus(anyLong())).thenReturn(false);

        // When - Then
        mockMvc.perform(patch("/api/v1/trainer/status")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(statusUpdateDto)))
                .andExpect(status().isOk())
                .andExpect(content().string(expectedMessage));
    }

    @ParameterizedTest
    @CsvSource({
            "trainer1, 2023-01-01, 2023-12-31, trainee1",
            "trainer2, , , ",
            "trainer3, 2023-06-01, , ",
            "trainer4, , 2023-12-31, trainee2",
            "trainer5, , , trainee3"
    })
    @DisplayName("Should get trainer trainings according to data")
    void getTrainerTrainings_ShouldReturnTrainings(
            String username, String periodFromStr, String periodToStr, String traineeUserName
    ) throws Exception {
        //Given
        var periodFrom = periodFromStr == null ? null : LocalDate.parse(periodFromStr);
        var periodTo = periodToStr == null ? null : LocalDate.parse(periodToStr);

        when(trainerService.findTrainerTrainingsByCriteria(username, periodFrom, periodTo, traineeUserName, TrainingType.YOGA))
                .thenReturn(Set.of(new TrainingView()));

        // When - Then
        mockMvc.perform(get("/api/v1/trainer/trainings")
                        .param("username", username)
                        .param("period-from", periodFromStr)
                        .param("period-to", periodToStr)
                        .param("trainee-username", traineeUserName)
                        .param("training-type", "YOGA")
                )
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isNotEmpty());
    }
}