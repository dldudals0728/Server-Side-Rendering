package com.SSR.CTSoft.Thymeleaf.service;

import com.SSR.CTSoft.Thymeleaf.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;

}
