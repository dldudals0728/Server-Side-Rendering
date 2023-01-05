package com.SSR.CTSoft.Thymeleaf.jwt;

import com.SSR.CTSoft.Thymeleaf.entity.User;
import com.SSR.CTSoft.Thymeleaf.repository.UserRepository;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.UnsupportedJwtException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;

@Component
@RequiredArgsConstructor
public class JwtRequestFilter extends OncePerRequestFilter {
    private final JwtTokenProvider jwtTokenProvider;
    private final UserRepository userRepository;
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        // jwt local storage 사용 시 해당 코드를 사용하여 header 에서 토큰을 받아오도록 한다.
        // final String token = request.getHeader("Authorization");

        // jwt cookie 사용 시 해당 코드를 사용하여 쿠키에서 토큰을 받아오도록 한다.
        System.out.println("doFilterInternal");
        System.out.println(Arrays.toString(request.getCookies()));
        try {
            String token = Arrays.stream(request.getCookies())
                    .filter(c -> c.getName().equals("jdhToken"))
                    .findFirst().map(Cookie::getValue)
                    .orElse(null);

            String adminId = null;
            String jwtToken = null;

            // Bearer token 인 경우 JWT 토큰 유효성 검사 진행
            if (token != null && token.startsWith("Bearer_")) {
                jwtToken = token.substring(7);
                try {
                    adminId = jwtTokenProvider.getUsernameFromToken(jwtToken);
                } catch (SignatureException e) {
                    System.out.println("JwtRequestFilter");
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
            } else {
                System.out.println("JwtRequestFilter");
                System.out.println("JWT Token does not begin with 'Bearer_' String");
            }

            // token 검증이 되고 인증 정보가 존재하지 않는 경우 spring security 인증 정보 저장
            if (adminId != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                User user = userRepository.findByUsername(adminId);

                if (jwtTokenProvider.validateToken(jwtToken, user)) {
                    UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());

                    authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                }
            }

            // accessToken 인증이 되었다면 refreshToken 재발급이 필요한 경우 재발급
            try {
                if (adminId != null) {
                    jwtTokenProvider.reGenerateRefreshToken(adminId);
                }
            } catch (Exception e) {
                System.out.println("[JwtRequestFilter] refreshToken 재발급 체크 중 문제 발생 : " + e.getMessage());
            }
        } catch (NullPointerException e) {
            System.out.println("null pointer exception : " + e.getMessage());
        }

        filterChain.doFilter(request, response);

    }

//    // Filter 에서 제외할 URL 설정
//    @Override
//    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
//        return EXC
//    }
}
