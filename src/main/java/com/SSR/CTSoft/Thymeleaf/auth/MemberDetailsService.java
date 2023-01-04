package com.SSR.CTSoft.Thymeleaf.auth;

import com.SSR.CTSoft.Thymeleaf.entity.User;
import com.SSR.CTSoft.Thymeleaf.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class MemberDetailsService implements UserDetailsService {
    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        System.out.println("member details service");
        User user = userRepository.findByUsername(username);
        System.out.println(user);
        if (user != null) {
            return new MemberDetails(user);
        }
        throw new UsernameNotFoundException("User not exist with name: " + username);
    }
}
