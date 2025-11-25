package com.example.mailbuddy.jwt;

import com.example.mailbuddy.jwt.JwtTokenProvider;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.List;

@Component
@RequiredArgsConstructor
public class OAuth2JwtSuccessHandler implements AuthenticationSuccessHandler {

    private final JwtTokenProvider jwtTokenProvider;

    // ★ S3 FE URL (배포 환경)
    private final String S3_FE = "http://mailbuddy-s3-fe.s3-website.ap-northeast-2.amazonaws.com/";

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication)
            throws IOException, ServletException {

        // ★ OAuth2 principal 에서 username(email) 추출
        String username = authentication.getName();

        // ★ 권한 리스트 추출 (ROLE_USER / ROLE_ADMIN)
        List<String> roles = authentication.getAuthorities()
                .stream()
                .map(a -> a.getAuthority())
                .toList();

        // ★ JWT 생성
        String token = jwtTokenProvider.createToken(username, roles);

        // ★ S3 FE 로 redirect + JWT 전달
        String redirectUrl = S3_FE + "?token=" + token;

        response.sendRedirect(redirectUrl);
    }
}
