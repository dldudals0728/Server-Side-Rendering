package com.SSR.CTSoft.Thymeleaf.config;

import com.SSR.CTSoft.Thymeleaf.jwt.JwtAuthenticationEntryPoint;
import com.SSR.CTSoft.Thymeleaf.jwt.JwtRequestFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    private final JwtRequestFilter jwtRequestFilter;
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

//        http.csrf().disable();

//        http.authorizeRequests()    // 요청에 의한 보안검사 시작
//                .antMatchers("/login").permitAll()
//                .antMatchers("/test").permitAll()// 어떤 요청에도 보안검사를 실시하기 전에, 로그인 페이지는 누구나 접근 가능하도록 한다!
//                .antMatchers("/signup").permitAll()
//                .anyRequest().authenticated()   // 어떤 요청에도 보안검사를 실시한다.
//                .and()
//                .formLogin()    // 보안 검증은 formLogin(로그인)방식으로 하겠다.
//                .loginPage("/login")
//                .loginProcessingUrl("/login")
//                .defaultSuccessUrl("/home")
//                .failureForwardUrl("/test");
//
//        return http.build();
        http.csrf().disable();

        http.authorizeRequests()
                .antMatchers("/user/**").authenticated()
//                .antMatchers("/admin/**").access("hasRole('ROLE_ADMIN')")
                .antMatchers("/join").anonymous()
                .anyRequest().permitAll()
//                .and()
//                .formLogin()
//                .loginPage("/login")
////                .loginProcessingUrl("/loginProc")
//                .loginProcessingUrl("/admin/authentication")
//                .defaultSuccessUrl("/")
//                .failureUrl("/login/error")
//                .and()
//                .logout()
//                .logoutSuccessUrl("/")

                .and()
                // exception 처리
                .exceptionHandling()
                .authenticationEntryPoint(jwtAuthenticationEntryPoint)
                .and()
                // Spring Security 에서 session 을 생성하거나 사용하지 않도록 설정
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                // JWT filter 적용
                .addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
