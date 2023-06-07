package com.cos.security.config;

import com.cos.security.config.oauth.PrincipalOauth2UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;


/**
 * OAuth 2
 * 1. 코드받기(인증완료)
 * 2. 엑세스 토큰 받기(사용자 정보접근 권한이 생김)
 * 3. 사용자 프로필 정보를 가져서
 * 4-1 그 정보를 토대로 회원가입을 자동으로 진행시키고 함
 * 4-2 존재하는 정보 외의 추가적인 정보가 필요하다면 새로운 로그인 폼으로 로그인을 유도해야함
 */



@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true) // secured 어노테이션 활성화, preAuthorize, postAuthorize 어노테이션 활성화
@RequiredArgsConstructor
public class SecurityConfig {

    private final PrincipalOauth2UserService oauth2UserService;

    // 패스워드 암호화
    @Bean
    public BCryptPasswordEncoder encodePwd() {
        return new BCryptPasswordEncoder();
    }
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf().disable();
        http.authorizeRequests()
                .antMatchers("/user/**").authenticated()
                .antMatchers("/manager/**").access("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')")
                .antMatchers("/admin/**").access("hasRole('ROLE_ADMIN')")
                .anyRequest().permitAll()
                .and()
                .formLogin()
                .loginPage("/loginForm")
                .loginProcessingUrl("/login") // /login 주소가 호출되면 시큐리티가 낚아채서 대신 로그인을 진행해줌( 컨트롤러에 /login 을 따로 만들지 않아도 됨)
                .defaultSuccessUrl("/")
                .and()
                .oauth2Login()
                .loginPage("/loginForm")// 구글 로그인 페이지로 이동 , 이제 로그인 후 처리 로직이 필요함. Tip. 구글 로그인이 완료가 되면 코드 X , (엑세스 토큰 + 사용자 프로필 정보 O)를 한번에 받음
                .userInfoEndpoint()
                .userService(oauth2UserService);

        return http.build();
    }
}
