package com.SSR.CTSoft.Thymeleaf.controller;

import com.SSR.CTSoft.Thymeleaf.auth.MemberDetails;
import com.SSR.CTSoft.Thymeleaf.dto.UserDto;
import com.SSR.CTSoft.Thymeleaf.entity.RefreshToken;
import com.SSR.CTSoft.Thymeleaf.entity.User;
import com.SSR.CTSoft.Thymeleaf.jwt.JwtTokenProvider;
import com.SSR.CTSoft.Thymeleaf.repository.RefreshTokenRepository;
import com.SSR.CTSoft.Thymeleaf.repository.UserRepository;
import com.SSR.CTSoft.Thymeleaf.service.UserService;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.UnsupportedJwtException;
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
    private final UserService userService;
    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtTokenProvider jwtTokenProvider;
//    @GetMapping("/")
//    public String index(@AuthenticationPrincipal MemberDetails memberDetails, Model model) {
//        if (memberDetails != null) {
//            System.out.println("member details is not null!");
//            System.out.println(memberDetails.getUsername());
//        } else {
//            System.out.println("member details is null!");
//        }
//        model.addAttribute("loginInfo", memberDetails);
//        return "index";
//    }
//    @GetMapping("/user")
//    public String user(@AuthenticationPrincipal MemberDetails memberDetails, Model model) {
//        HashMap<String, String> map = new HashMap<>();
//        map.put("username", memberDetails.getUsername());
//        map.put("email", memberDetails.getUser().getEmail());
//        model.addAttribute("user", map);
//        return "userPage";
//    }

    @GetMapping("/")
    public String index(Model model) {

//        model.addAttribute("loginInfo", memberDetails);
        return "index";
    }

    @GetMapping("/user")
    public String user(Model model) {
        HashMap<String, String> map = new HashMap<>();
        model.addAttribute("user", map);
        return "userPage";
    }

    @GetMapping("/join")
    public String join(Model model) {
        return "join";
    }

    @GetMapping("/join/error")
    public String joinError(Model model) {
        model.addAttribute("errorMessage", "?????? ????????? ???????????????.");
        return "join";
    }

    @GetMapping("/login")
    public String login(Model model) {
        return "login";
    }

    @GetMapping("/login/error")
    public String loginError(Model model) {
        model.addAttribute("errorMessage", "????????? ?????? ???????????? ???????????????.");
        return "login";
    }
    @PostMapping("/joinProc")
    public String joinProc(User user) {
        User joinedUser = userService.joinUser(user);
        if (joinedUser == null) {
            return "redirect:/join/error";
        }
        return "redirect:/";
    }

    // JWT Token??? ????????? login post mapping url
    @PostMapping("/admin/authentication")
    public String testJwtTokenGet(UserDto input, HttpServletRequest request, HttpServletResponse response) throws Exception {
        System.out.println("user controller login");
        System.out.println(input.toString());
        Map<String, Object> returnMap = new HashMap<>();
        User user = userService.loginUser(input.getUsername(), input.getPassword());
        if (user == null) {
            return "redirect:/login/error";
        }
        Map<String, String> tokens = jwtTokenProvider.generateTokenSet(user.getUsername());
        String accessToken = URLEncoder.encode(tokens.get("accessToken"), StandardCharsets.UTF_8);
        String refreshToken = URLEncoder.encode(tokens.get("refreshToken"), StandardCharsets.UTF_8);

        System.out.println("[JWT ??????] accessToken : " + accessToken);
        System.out.println("[JWT ??????] refreshToken : " + refreshToken);

        Cookie cookie = new Cookie("jdhToken", "Bearer_" + accessToken);
        cookie.setPath("/");
        cookie.setMaxAge(60 * 60);  // ???????????? 1??????

//        cookie.setHttpOnly(true);
        response.addCookie(cookie);

        RefreshToken refreshTokenEntity = new RefreshToken();
        refreshTokenEntity.setUserIdx(user.getId());
        refreshTokenEntity.setRefreshToken("Bearer_" + refreshToken);
        refreshTokenRepository.save(refreshTokenEntity);

        returnMap.put("result", "success");
        returnMap.put("msg", "JWT ????????? ?????????????????????.");
//        return returnMap;
        return "redirect:/";
    }

    // JWT Token ?????????
    @PostMapping("/admin/refresh")
    public String testTwtTokenRefresh(UserDto userDto, HttpServletRequest request, HttpServletResponse response) throws Exception {
        String refreshToken = null;
        String adminId = "";

        // ????????? ?????? ??????
        User currentUser = userService.currentUser(userDto.getUsername());

        // refreshToken ??????
        RefreshToken refreshTokenEntity = refreshTokenRepository.findByUserIdx(currentUser.getId());

        // token ?????? ?????? ??????
        if (refreshTokenEntity == null) {
            System.out.println("refresh token information not exists");
            return "login";
        } else {
            refreshToken = refreshTokenEntity.getRefreshToken();
        }

        // refreshToken ??????
        boolean tokenFl = false;
        try {
            refreshToken = refreshToken.substring(7);
            adminId = jwtTokenProvider.getUsernameFromToken(refreshToken);
            tokenFl = true;
        } catch (SignatureException e) {
            System.out.println("User");
            System.out.println("invalid Jwt signature : " + e.getMessage());
        } catch (MalformedJwtException e) {
            System.out.println("JwtRequestFilter");
            System.out.println("invalid Jwt token : " + e.getMessage());
        } catch (ExpiredJwtException e) {
            System.out.println("JwtRequestFilter");
            System.out.println("JWT token is expired : " + e.getMessage());
        } catch (UnsupportedJwtException e) {
            System.out.println("JwtRequestFilter");
            System.out.println("JWT token is unsupported : " + e.getMessage());
        } catch (IllegalArgumentException e) {
            System.out.println("JwtRequestFilter");
            System.out.println("JWT claims string is empty : " + e.getMessage());
        }

        // refreshToken ??? ?????? ???????????? ??????
        if (!tokenFl) {
            System.out.println("refresh token??? ?????????????????? ????????? ???????????? ????????????.");
            return "login";
        }

        if (adminId != null && !adminId.equals("")) {
            // JWT ??????
            String tokens = jwtTokenProvider.generateAccessToken(currentUser.getUsername());
            String accessToken = URLEncoder.encode(tokens, StandardCharsets.UTF_8);

            System.out.println("[JWT ?????????] accessToken : " + accessToken);

            // JWT ?????? ??????
            Cookie cookie = new Cookie("jdhToken", "Bearer_" + accessToken);

//            cookie.setHttpOnly(true);

            response.addCookie(cookie);
            System.out.println("JWT??? ?????????????????????.");
            return "redirect:/";
        } else {
            System.out.println("access token ?????? ??? ????????? ??????????????????.");
            return "login";
        }
    }
}
