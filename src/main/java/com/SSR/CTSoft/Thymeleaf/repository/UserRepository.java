package com.SSR.CTSoft.Thymeleaf.repository;

import com.SSR.CTSoft.Thymeleaf.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, Long> {
    User findByUsername(String username);
}
