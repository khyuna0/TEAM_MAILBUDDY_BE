package com.example.mailbuddy.config;

import org.springframework.messaging.Message;
import org.springframework.messaging.MessageChannel;
import org.springframework.messaging.simp.stomp.StompCommand;
import org.springframework.messaging.simp.stomp.StompHeaderAccessor;
import org.springframework.messaging.support.ChannelInterceptor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

// 2단계 :
// 웹소켓 세션이 만들어질 때 로그인한 사용자 정보를 세션에 실어주는 역할
// 이 메세지를 누가 보냈는지를 서버가 알 수 있게 하는 역할임

// 메세지가 서버에 들어오기 직전에 가로채는 인터셉터
// 우리 채팅 흐름 :  (보낸 사람) -> (서버) -> (받는 사람)
@Component
public class WebSocketAuthInterceptor implements ChannelInterceptor {

    @Override // 서버로 들어오는 STOMP 메세지를 잡아서 처리 (서버로 전송되기 전 시점)
    public Message<?> preSend(Message<?> message, MessageChannel channel) {
        StompHeaderAccessor accessor = StompHeaderAccessor.wrap(message);

        if(StompCommand.CONNECT.equals((accessor.getCommand()))) { // 웹소켓에 연결 된 상태일 때만 인증 정보 주입
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            if(auth != null && auth.isAuthenticated()) {
                accessor.setUser(auth); // 인증이 유효하면 웹소켓 세션에 auth 등록
            }
        }
        return message;
    }
}