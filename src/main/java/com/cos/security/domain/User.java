package com.cos.security.domain;

import com.cos.security.domain.base.BaseEntity;
import lombok.*;

import javax.persistence.*;
@Data
@Entity
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
public class User extends BaseEntity {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String username;
    private String password;
    private String email;

    @Enumerated(EnumType.STRING)
    private Role role;

    private String provider;
    private String providerId;

    @Builder
    public User(Long id, String username, String password, String email, String role, String provider, String providerId) {
        this.id = id;
        this.username = username;
        this.password = password;
        this.email = email;
        this.role = Role.valueOf(role);
        this.provider = provider;
        this.providerId = providerId;

        // oauth 로그인시
        // username = "google_{sub}"
        // password = "암호화(겟인데어)"
        // email : 요청으로 받아온 토큰 + 정보에 있는 이메일 그대로
        // role : "ROLE_USER"
        // provider : "google"
        // providerId : "{sub}"
    }

}
