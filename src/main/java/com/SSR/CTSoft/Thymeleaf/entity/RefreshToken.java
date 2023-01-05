package com.SSR.CTSoft.Thymeleaf.entity;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

import javax.persistence.*;

@Entity
@Table
@Getter
@Setter
@ToString
public class RefreshToken {
    @Id
    @Column(name = "refresh_token_idx")
    @GeneratedValue(strategy = GenerationType.AUTO)
    private long id;

    @Column
    private long userIdx;

    @Lob
    @Column
    private String refreshToken;
}
