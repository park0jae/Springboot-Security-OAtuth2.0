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
                // 특정 리소스에 대한 권한을 설정 ( 인증처리 )
                .antMatchers("/user/**").authenticated()
                // 특정 리소스에 대한 권한 설정 (권한 여부에 따른 접근성 판단)
                .antMatchers("/manager/**").access("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')")
                .antMatchers("/admin/**").access("hasRole('ROLE_ADMIN')")
                // 외의 모든 요청에 대해서는 인증절차 없이 접근 허용
                .anyRequest().permitAll()
                .and()
                // 로그인 페이지와 기타 로그인 처리 및 성공 실패 처리를 사용하겠다는 의미
                .formLogin()
                // 사용자가 정의한 로그인 페이지 사용 시 선언
                .loginPage("/loginForm")
                // 템플릿의 폼 action과 일치해야 함
                // UsernamePasswordAuthenticationFilter가 실행
                .loginProcessingUrl("/login") // /login 주소가 호출되면 시큐리티가 낚아채서 대신 로그인을 진행해줌( 컨트롤러에 /login 을 따로 만들지 않아도 됨)
                // 정상적으로 인증 성공 시 이동하는 페이지
                .defaultSuccessUrl("/")
                .and()
                // OAuth2 로그인에 대한 설정을 시작하겠다는 의미
                .oauth2Login()
                .loginPage("/loginForm")// 구글 로그인 페이지로 이동 , 이제 로그인 후 처리 로직이 필요함. Tip. 구글 로그인이 완료가 되면 코드 X , (엑세스 토큰 + 사용자 프로필 정보 O)를 한번에 받음
                // oauth2 Login에 성공하면 oauth2UserService에서 설정을 진행하겠다라는 의미입니다.
                .userInfoEndpoint()
                .userService(oauth2UserService);
        return http.build();
    }
}
