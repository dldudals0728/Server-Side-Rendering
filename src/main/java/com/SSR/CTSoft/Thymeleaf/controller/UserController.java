package com.SSR.CTSoft.Thymeleaf.controller;

import com.SSR.CTSoft.Thymeleaf.auth.MemberDetails;
import com.SSR.CTSoft.Thymeleaf.dto.UserDto;
import com.SSR.CTSoft.Thymeleaf.entity.RefreshToken;
import com.SSR.CTSoft.Thymeleaf.entity.User;
import com.SSR.CTSoft.Thymeleaf.jwt.JwtTokenProvider;
import com.SSR.CTSoft.Thymeleaf.repository.RefreshTokenRepository;
import com.SSR.CTSoft.Thymeleaf.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

@CrossOrigin
@Controller
@RequiredArgsConstructor
public class UserController {
    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtTokenProvider jwtTokenProvider;
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

    @PostMapping("/admin/authentication")
    public String testJwtTokenGet(UserDto input, HttpServletRequest request, HttpServletResponse response) throws Exception {
        System.out.println("user controller login");
        System.out.println(input.toString());
        Map<String, Object> returnMap = new HashMap<>();
        User user = userRepository.findByUsername(input.getUsername());
        if (user == null) {
            return "redirect:/login/error";
        }
        Map<String, String> tokens = jwtTokenProvider.generateTokenSet(user.getUsername());
        String accessToken = URLEncoder.encode(tokens.get("accessToken"), StandardCharsets.UTF_8);
        String refreshToken = URLEncoder.encode(tokens.get("refreshToken"), StandardCharsets.UTF_8);

        System.out.println("[JWT 발급] accessToken : " + accessToken);
        System.out.println("[JWT 발급] refreshToken : " + refreshToken);

        Cookie cookie = new Cookie("jdhToken", "Bearer_" + accessToken);
        cookie.setPath("/");
        cookie.setMaxAge(60 * 60);  // 유효기간 1시간

//        cookie.setHttpOnly(true);
        response.addCookie(cookie);

        RefreshToken refreshTokenEntity = new RefreshToken();
        refreshTokenEntity.setUserIdx(user.getId());
        refreshTokenEntity.setRefreshToken("Bearer_" + refreshToken);
        refreshTokenRepository.save(refreshTokenEntity);

        returnMap.put("result", "success");
        returnMap.put("msg", "JWT 발급이 완료되었습니다.");
//        return returnMap;
        return "redirect:/";
    }
}
