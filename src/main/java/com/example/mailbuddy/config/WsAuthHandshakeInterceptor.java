package com.example.mailbuddy.config;

import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.lang.NonNull;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.socket.WebSocketHandler;
import org.springframework.web.socket.server.HandshakeInterceptor;

import java.util.Map;

// 1단계 :
// 웹소켓 연결 시도 직전에 동작하는 클래스 
// 로그인하지 않은 사용자의 접속을 차단한다.
// 로그인 확인 되면 username을 웹소켓 세션에 저장
public class WsAuthHandshakeInterceptor implements HandshakeInterceptor {

    @Override   // 웹소켓 연결 전에 동작
    public boolean beforeHandshake(@NonNull ServerHttpRequest request,
                                   @NonNull ServerHttpResponse response,
                                   @NonNull WebSocketHandler wsHandler,
                                   @NonNull Map<String, Object> attributes) {
        // 현재 인증 정보 가져옴
        // 일반 로그인 사용자 → UsernamePasswordAuthenticationToken
        // 구글 로그인 사용자 → OAuth2AuthenticationToken
        // 따로 구별은 안함
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        // 비로그인 차단
        if (auth == null || !auth.isAuthenticated()) {
            return false;
        }

        // 로그인한 유저의 username을 웹소켓 세션에 저장
        String username = auth.getName();
        attributes.put("username", username);
        attributes.put("bucketKey", username); // 사용자별 키 - 웹소켓 연결을 묶는 키로 사용
        return true;
    }

    // 연결 완료 후에 사용되는 콜백. 지금은 기능 없습니다.
    @Override
    public void afterHandshake(@NonNull ServerHttpRequest request,
                               @NonNull ServerHttpResponse response,
                               @NonNull WebSocketHandler wsHandler,
                               Exception exception) { }
}