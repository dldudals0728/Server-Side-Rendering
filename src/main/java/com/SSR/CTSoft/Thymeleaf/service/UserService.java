package com.SSR.CTSoft.Thymeleaf.service;

import com.SSR.CTSoft.Thymeleaf.entity.User;
import com.SSR.CTSoft.Thymeleaf.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;

@Service
@Transactional
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public User loginUser(String username, String password) {
        User selectedUser = userRepository.findByUsername(username);
        if (selectedUser == null) {
            return null;
        }

        if (!passwordEncoder.matches(password, selectedUser.getPassword())) {
            return null;
        }

        return selectedUser;
    }

    public User joinUser(User user) {
        if (this.isJoinedUser(user.getUsername())) {
            return null;
        }
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        user.setRole("ROLE_USER");
        // spring security 에서 로그인 할 경우, password encoding이 안되어있으면 로그인 자체가 안됨!
        return userRepository.save(user);
    }

    public boolean isJoinedUser(String username) {
        User user = userRepository.findByUsername(username);
        return user != null;
    }

    public User currentUser(String username) {
        return userRepository.findByUsername(username);
    }
}
