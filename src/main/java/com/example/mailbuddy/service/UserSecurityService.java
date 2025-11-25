package com.example.mailbuddy.service;

import com.example.mailbuddy.entity.User;
import com.example.mailbuddy.repository.UserRepository;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.Optional;

@Service
public class UserSecurityService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Override // 로그인
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        User user = userRepository.findByUsername(username)
                .orElseThrow(()->new UsernameNotFoundException("사용자 없음"));

        return org.springframework.security.core.userdetails.User
                .withUsername(user.getUsername())
                .password(user.getPassword())
                .roles("USER")
                .build();
    }

    // 인증된 사용자의 구글 아이디를 통해서 사용자 엔티티 가져오기
    public User getUserfindByGoogleEmail(OAuth2AuthenticationToken authentication) {
        OAuth2User oauth = authentication.getPrincipal();
        String googleEmail = oauth.getAttribute("email");
        return userRepository.findByGoogleEmail(googleEmail)
                .orElseThrow(() -> new UsernameNotFoundException("User not found" + googleEmail));
    }

    // 인증된 사용자를 찾지 못한 경우 에러 메시지 출력 (따로 메서드 만들었는데 굳이 ..)
    public boolean isAuthenticated(Authentication authentication) {
        return authentication != null && authentication.isAuthenticated();
    }

}
