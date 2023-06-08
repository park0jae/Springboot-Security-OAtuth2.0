package com.cos.security.config.oauth;

import com.cos.security.config.auth.PrincipalDetails;
import com.cos.security.domain.Role;
import com.cos.security.domain.User;
import com.cos.security.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;
    // 구글로 부터 받은 userRequest 데이터에 대한 후처리되는 함수
    // 함수 종료 시 @AuthenticationPrincipal 어노테이션이 만들어진다.
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        log.info("getClientRegistration={}", userRequest.getClientRegistration()); // registrationID로 어떤 OAuth (google, naver ... 등등) 로 로그인 했는지 확인 가능
        log.info("getAccessToken={}", userRequest.getAccessToken().getTokenValue());


        OAuth2User oAuth2User = super.loadUser(userRequest);

        // 구글로그인 버튼 클릭 --> 구글 로그인 창 -> 로그인을 완료 -> Code를 리턴 (OAuth-Client 라이브러리가 받아줌) -> 코드를 통해 AccessToken을 요청
        // userRequest 정보가 AccessToken을 받는 것 까지임 --> 구글로부터 회원 프로필 받아야 함(이 때 사용하는 것이 loadUser 함수임 , 호출) --> 회원 프로필을 받음
        log.info("getAttributes={}", oAuth2User.getAttributes());

        String provider = userRequest.getClientRegistration().getClientId(); // google
        String providerId = oAuth2User.getAttribute("sub");
        String username = provider+ "_" + providerId; // google_~~~~~~~
        String email = oAuth2User.getAttribute("email");
        Role role = Role.valueOf("ROLE_USER");

        User userEntity = userRepository.findByUsername(username);

        if(userEntity == null){
            log.info("첫 로그인입니다.");
            userEntity = User.builder()
                    .username(username)
                    .email(email)
                    .role(role.toString())
                    .provider(provider)
                    .providerId(providerId)
                    .build();
            userRepository.save(userEntity);
        }else {
            log.info("이미 가입된 회원입니다.");
        }
        // 회원가입을 강제로 진행해볼 예정
        return new PrincipalDetails(userEntity, oAuth2User.getAttributes());
    }
}
