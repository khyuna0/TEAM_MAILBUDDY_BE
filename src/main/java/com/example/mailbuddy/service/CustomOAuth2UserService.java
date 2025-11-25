package com.example.mailbuddy.service;

import com.example.mailbuddy.entity.UserRole;
import com.example.mailbuddy.entity.User;
import com.example.mailbuddy.repository.UserRepository;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Collection;
import java.util.List;
import java.util.Map;

@Service
// 구글 OAuth 로그인 시 세션 username으로 DB 회원찾아 구글 이메일 저장하는 서비스
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    @Autowired
    private UserRepository userRepository;

    private final HttpSession httpSession;  // 현재 세션에서 폼 로그인 유저 찾기

    public CustomOAuth2UserService(HttpSession httpSession) {
        this.httpSession = httpSession;
    }

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);

        // 구글에서 받는 유저 속성
        Map<String, Object> attributes = oAuth2User.getAttributes();

        // 구글에서 받은 이메일
        String googleEmail = (String) attributes.get("email");
        if (googleEmail == null) {
            throw new OAuth2AuthenticationException(new OAuth2Error("email_not_found"), "Google email not found");
        }

        // 현재 세션에서 폼 로그인한 유저명 가져오기
        String loggedInUsername = (String) httpSession.getAttribute("LOGGED_IN_USER");

        // 이미 연동 됐는지 확인용 -> 초기화
        User linkedUser = null;

        if (loggedInUsername != null) {
            // 세션에 있는 폼 로그인 유저
            User user = userRepository.findByUsername(loggedInUsername)
                    .orElseThrow(() -> new UsernameNotFoundException("User not found: " + loggedInUsername));

            //이 구글 이메일을 이미 쓰고있는 유저가 있는지 확인
            userRepository.findByGoogleEmail(googleEmail).ifPresent(existing -> {
                //세션 유저랑 다르면 = 이미 다른아이디에 연동된 상태
                if (!existing.getId().equals(user.getId())) {
                    throw new OAuth2AuthenticationException(
                            new OAuth2Error("google_email_already_linked",
                            "이미 다른계정(" + existing.getUsername() + ")에 연동된 구글 계정 입니다.",
                            null
                    ),
                    "이미 다른 계정에 연동된 구글 계정 입니다."
                            );
                }
            });

            // 구글메일 연동 한 적 없다면 -> 구글 이메일을 유저 DB에 저장
            user.setGoogleEmail(googleEmail);
            linkedUser = userRepository.save(user);
        }

//        final User finalUser = userRepository.findByGoogleEmail(googleEmail)
//                .orElseThrow(() -> new UsernameNotFoundException("User not found by Google email: " + googleEmail));

//        // DB 조회, 없으면 권한 생성
//        User user = userRepository.findByGoogleEmail(googleEmail)
//                .orElseGet(() -> userRepository.save(
//                        User.builder()
//                                .userRole(UserRole.USER)
//                                .build()
//                ));
//
//
        //Collection<SimpleGrantedAuthority> authorities = List.of(new SimpleGrantedAuthority("ROLE_"+user.getUserRole().name()));
        // .name()을 쓰면 ENUM 타입을 순수 문자열로 꺼낼 수 있음

        // 권한 세팅
        Collection<SimpleGrantedAuthority> authorities =
                List.of(new SimpleGrantedAuthority("ROLE_" + linkedUser.getUserRole().name()));


        //OAuth2User 생성
        final User finalUser = linkedUser;

        return new DefaultOAuth2User(
                authorities,
                attributes,
                "email") {
            @Override
            public String getName() {
                return finalUser.getUsername();
            }
        };


    }
}
