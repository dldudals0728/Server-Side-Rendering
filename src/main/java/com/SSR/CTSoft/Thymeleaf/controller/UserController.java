package com.SSR.CTSoft.Thymeleaf.controller;

import com.SSR.CTSoft.Thymeleaf.entity.User;
import com.SSR.CTSoft.Thymeleaf.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

@CrossOrigin
@Controller
@RequestMapping("/")
@RequiredArgsConstructor
public class UserController {
    private final PasswordEncoder passwordEncoder;

    private final UserRepository userRepository;
    @GetMapping("/user")
    public @ResponseBody String user(Model model) {
        return "user";
    }

    @GetMapping("/join")
    public String join(Model model) {
        return "join";
    }

    @GetMapping("/login")
    public String login(Model model) {
        return "login";
    }

    @PostMapping("/joinProc")
    public String joinProc(User user) {
        String rawPassword = user.getPassword();
        String encPassword = passwordEncoder.encode(rawPassword);
        user.setPassword(encPassword);
        user.setRole("ROLE_USER");
        // spring security 에서 로그인 할 경우, password encoding이 안되어있으면 로그인 자체가 안됨!
        userRepository.save(user);
        return "redirect:/";
    }
}
