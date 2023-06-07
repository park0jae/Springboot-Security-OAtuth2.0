package com.cos.security.controller;

import com.cos.security.domain.Role;
import com.cos.security.domain.User;
import com.cos.security.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
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

    @GetMapping("/")
    public String index(){
        return "index";
    }
    @ResponseBody
    @GetMapping("/user")
    public String user(){
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
