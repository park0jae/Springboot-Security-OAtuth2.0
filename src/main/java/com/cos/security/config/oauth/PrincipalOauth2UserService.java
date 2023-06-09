package com.cos.security.config.oauth;

import com.cos.security.config.auth.PrincipalDetails;
import com.cos.security.config.oauth.provider.GoogleUserInfo;
import com.cos.security.config.oauth.provider.KakaoUserInfo;
import com.cos.security.config.oauth.provider.NaverUserInfo;
import com.cos.security.config.oauth.provider.OAuth2UserInfo;
import com.cos.security.domain.User;
import com.cos.security.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.Optional;

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
        OAuth2UserInfo oAuth2UserInfo = null;

        // 구글로그인 버튼 클릭 --> 구글 로그인 창 -> 로그인을 완료 -> Code를 리턴 (OAuth-Client 라이브러리가 받아줌) -> 코드를 통해 AccessToken을 요청
        // userRequest 정보가 AccessToken을 받는 것 까지임 --> 구글로부터 회원 프로필 받아야 함(이 때 사용하는 것이 loadUser 함수임 , 호출) --> 회원 프로필을 받음
        log.info("getAttributes={}", oAuth2User.getAttributes());

        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        log.info("registrationId={}", registrationId);

        switch (registrationId) {
            case "google":
                log.info("구글 로그인 요청");
                oAuth2UserInfo = new GoogleUserInfo(oAuth2User.getAttributes());
                break;
            case "naver":
                log.info("네이버 로그인 요청");
                oAuth2UserInfo = new NaverUserInfo((Map<String, Object>) oAuth2User.getAttributes().get("response"));
                break;
            case "kakao":
                log.info("카카오 로그인 요청");
                oAuth2UserInfo = new KakaoUserInfo(oAuth2User.getAttributes());
                log.info("getAttributes={}", oAuth2User.getAttributes());
                break;
            default:
                log.info("로그인 실패");
                break;
        }

        Optional<User> userEntity = userRepository.findByProviderAndProviderId(oAuth2UserInfo.getProvider(), oAuth2UserInfo.getProviderId());

        User user;
        if(userEntity.isPresent()){
            user = userEntity.get();
            user.setEmail(oAuth2UserInfo.getEmail());
            userRepository.save(user);
        }else {
            log.info("email={}", oAuth2UserInfo.getEmail());
            user= User.builder()
                    .username(oAuth2UserInfo.getProvider() + "_" + oAuth2UserInfo.getProviderId())
                    .email(oAuth2UserInfo.getEmail())
                    .provider(oAuth2UserInfo.getProvider())
                    .providerId(oAuth2UserInfo.getProviderId())
                    .role("ROLE_USER")
                    .build();
            userRepository.save(user);
        }
        // 회원가입을 강제로 진행해볼 예정
        return new PrincipalDetails(user, oAuth2User.getAttributes());
    }
}
