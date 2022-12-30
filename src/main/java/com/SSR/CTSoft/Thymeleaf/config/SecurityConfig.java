package com.SSR.CTSoft.Thymeleaf.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http.csrf().disable();

        http.authorizeRequests()    // 요청에 의한 보안검사 시작
                .antMatchers("/login").permitAll()  // 어떤 요청에도 보안검사를 실시하기 전에, 로그인 페이지는 누구나 접근 가능하도록 한다!
                .anyRequest().authenticated()   // 어떤 요청에도 보안검사를 실시한다.
                .and()
                .formLogin()    // 보안 검증은 formLogin(로그인)방식으로 하겠다.
                .loginPage("/login")
                .defaultSuccessUrl("/home")
                .failureForwardUrl("/test");

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
