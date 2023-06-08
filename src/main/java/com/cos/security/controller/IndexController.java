package com.cos.security.controller;

import com.cos.security.config.auth.PrincipalDetails;
import com.cos.security.domain.Role;
import com.cos.security.domain.User;
import com.cos.security.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Slf4j
@Controller
@RequiredArgsConstructor
public class IndexController {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @ResponseBody
    @GetMapping("/test/login")
    public String testLogin(Authentication authentication,
                            // 해당 어노테이션으로 세션 정보에 접근이 가능 , principalDetails가 userDetails를 implements 했기 때문에 변환이 가능
                            //@AuthenticationPrincipal UserDetails userDetails,
                            @AuthenticationPrincipal PrincipalDetails userDetails){ // DI (의존성 주입)
        PrincipalDetails principalDetails =  (PrincipalDetails) authentication.getPrincipal();
        log.info("authentication ={}",principalDetails.getUser());

        log.info("userDetails={}", userDetails.getUsername());

        return "세션 정보 확인하기";
    }

    @ResponseBody
    @GetMapping("/test/oauth/login")
    public String testOauthLogin(Authentication authentication,
                                 @AuthenticationPrincipal OAuth2User oauth){ // DI (의존성 주입)
        OAuth2User oAuth2User =  (OAuth2User) authentication.getPrincipal();
        log.info("authentication ={}",oAuth2User.getAttributes());
        log.info("oauth2User={}", oauth.getAttributes());

        return "OAuth 세션 정보 확인하기";
    }

    // localhost:8080 or localhost:8080/
    @GetMapping({",","/"})
    public String index(){
        return "index";
    }

    // OAuth 로그인을 해도 PrincipalDetails
    // 일반 로그인을 해도 PrincipalDetails로 받음
    //
    @ResponseBody
    @GetMapping("/user")
    public String user(@AuthenticationPrincipal PrincipalDetails principalDetails){
        log.info("principalDetails ={}", principalDetails.getUser());

        return "user";
    }
    @ResponseBody
    @GetMapping("/admin")
    public String admin(){
        return "admin";
    }
    @ResponseBody
    @GetMapping("/manager")
    public String manager(){
        return "manager";
    }
    @GetMapping("/loginForm")
    public String loginForm(){
        return "loginForm";
    }

    @GetMapping("/joinForm")
    public String joinForm(){
        return "joinForm";
    }

    @PostMapping("/join")
    public String join(User user){
        log.info("user ={}", user);
        user.setRole(Role.valueOf("ROLE_USER"));
        String rawPassword = user.getPassword();
        String encPassword = bCryptPasswordEncoder.encode(rawPassword);
        user.setPassword(encPassword);
        userRepository.save(user); // 회원가입은 잘 되지만, 비밀번호가 만약 1234 라면 ==> 시큐리티로 로그인을 할 수 없는데, 이유는 패스워드가 암호화가 되어있지 않기 때문
        return "redirect:/loginForm";
    }

    @Secured("ROLE_ADMIN")
    @ResponseBody
    @GetMapping("/info")
    public String info(){
        return "개인정보";
    }

    @PreAuthorize("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
    @ResponseBody
    @GetMapping("/data")
    public String data(){
        return "데이터 정보";
    }
}
