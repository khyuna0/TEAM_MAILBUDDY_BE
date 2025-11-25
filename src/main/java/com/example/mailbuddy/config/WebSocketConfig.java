package com.example.mailbuddy.config;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.messaging.simp.config.ChannelRegistration;
import org.springframework.messaging.simp.config.MessageBrokerRegistry;
import org.springframework.web.socket.config.annotation.EnableWebSocketMessageBroker;
import org.springframework.web.socket.config.annotation.StompEndpointRegistry;
import org.springframework.web.socket.config.annotation.WebSocketMessageBrokerConfigurer;

// 웹소켓 연결 활성화
// STOMP 프로토콜 기반 메세지 송수신 가능하게 설정하는 클래스
//WebSocket은 단순 연결/전송만 제공하고 STOMP는 그 위에서 아래 기능을 제공한다

// 1 : 1 채팅
// 구독 subscribe : 클라이언트가 서버에 특정 주제(destination)를 구독하여 해당 주제로 전송되는 메시지를 실시간으로 받기 위해 요청하는 기능
// 발행 publish : 클라이언트 -> 서버 방향 메세지

// 방송 : 방 안의 모든 유저에게 메세지를 뿌리는 방식
// 특정 유저에게 DM(sendToUser)

// 제가 만든 기능은 (보낸 사람) -> (서버) -> (받는 사람) 단순한 흐름
@Configuration
@EnableWebSocketMessageBroker
@RequiredArgsConstructor
public class WebSocketConfig implements WebSocketMessageBrokerConfigurer {

    @Autowired
    private WebSocketAuthInterceptor webSocketAuthInterceptor;

    //  클라이언트(React, JS 등)가 서버에 WebSocket으로 연결할 수 있는 엔드포인트 설정
    @Override
    public void registerStompEndpoints(StompEndpointRegistry registry) {
        registry.addEndpoint("/ws/chat")  // 주소 (메세지의 목적지 / USER 별 채팅 방이라고 생각하면 될 듯?)
                .setAllowedOriginPatterns("*") // CORS 허용 (모든 출처에서 연결 가능)
                .addInterceptors(new WsAuthHandshakeInterceptor()) // 연결 전 1단계 인터셉터 (비로그인 유저 차단)
                .withSockJS(); // 클라이언트와 SockJS 연결 허용
    }

    // MessageBroker : 메시지를 송신자로부터 수신하여 이를 수신자에게 전달하는 중간 매개체
    // 메시지를 주고받는 규칙(경로, Prefix)을 설정하는 부분
    // "/app" : 클라이언트 → 서버로 메시지 보낼 때 사용 (수신)
    // "/topic" : 서버 → 클라이언트로 메시지를 보낼 때 사용 (송신)
    @Override
    public void configureMessageBroker(MessageBrokerRegistry registry) {
        registry.enableSimpleBroker("/topic"); // 이 prefix가 붙은 주소로 메시지를 전송
        registry.setApplicationDestinationPrefixes("/app"); // 이 prefix가 붙은 주소로 메시지를 전달 받음
    }

    @Override
    public void configureClientInboundChannel(ChannelRegistration registration) {
        registration.interceptors(webSocketAuthInterceptor); // 연결 후 2단계 인터셉터 (로그인 정보 있으면 웹소켓 세션에 사용자 정보 등록)

        // WebSocket 연결(STOMP 세션 생성) 시점에 가로채는 클래스.
    }

}