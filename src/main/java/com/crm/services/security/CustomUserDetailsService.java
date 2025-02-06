package com.crm.services.security;

import com.crm.repositories.TraineeRepo;
import com.crm.repositories.TrainerRepo;
import com.crm.repositories.entities.User;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {
    private final TraineeRepo traineeRepo;
    private final TrainerRepo trainerRepo;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        var user = findUserByUsername(username);

        return mapToUserDetails(user);
    }

    private User findUserByUsername(String username) {
        return traineeRepo.findByUserName(username)
                .map(trainer -> (User) trainer)
                .or(() -> trainerRepo.findByUserName(username))
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
    }

    private UserDetails mapToUserDetails(User user) {
        return org.springframework.security.core.userdetails.User.builder()
                .username(user.getUserName())
                .password(user.getPassword())
                .build();
    }
}
