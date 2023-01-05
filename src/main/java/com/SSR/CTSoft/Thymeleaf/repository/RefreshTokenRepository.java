package com.SSR.CTSoft.Thymeleaf.repository;

import com.SSR.CTSoft.Thymeleaf.entity.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    RefreshToken findByUserIdx(long idx);
}
