package com.SSR.CTSoft.Thymeleaf.controller;

import com.SSR.CTSoft.Thymeleaf.auth.MemberDetails;
import com.SSR.CTSoft.Thymeleaf.entity.User;
import com.SSR.CTSoft.Thymeleaf.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;

@CrossOrigin
@Controller
@RequiredArgsConstructor
public class UserController {
    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;
    @GetMapping("/")
    public String index(@AuthenticationPrincipal MemberDetails memberDetails, Model model) {
        if (memberDetails != null) {
            System.out.println("member details is not null!");
            System.out.println(memberDetails.getUsername());
        } else {
            System.out.println("member details is null!");
        }
        model.addAttribute("loginInfo", memberDetails);
        return "index";
    }
    @GetMapping("/user")
    public String user(@AuthenticationPrincipal MemberDetails memberDetails, Model model) {
        HashMap<String, String> map = new HashMap<>();
        map.put("username", memberDetails.getUsername());
        map.put("email", memberDetails.getUser().getEmail());
        model.addAttribute("user", map);
        return "userPage";
    }

    @GetMapping("/join")
    public String join(Model model) {
        return "join";
    }

    @GetMapping("/login")
    public String login(Model model) {
        return "login";
    }

    @GetMapping("/login/error")
    public String loginError(Model model) {
        model.addAttribute("errorMessage", "아이디 또는 비밀번호 오류입니다.");
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
