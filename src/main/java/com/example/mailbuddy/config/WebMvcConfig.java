package com.example.mailbuddy.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * 전역 CORS 설정 클래스
 *  - React 프론트(EC2 또는 localhost)에서
 *    Spring Boot 백엔드(EC2:8888)로 API 요청을 할 수 있도록 허용하기 위함.
 */
@Configuration
public class WebMvcConfig implements WebMvcConfigurer {

    @Override
    public void addCorsMappings(CorsRegistry registry) {

        registry.addMapping("/**") // 백엔드의 모든 API 경로에 CORS 적용
                .allowedOrigins(
                        // 로컬 개발 환경 (React dev server)
                        "http://localhost:3000",

                        // 배포된 프론트 (EC2로 제공되는 React build)
                        "http://52.79.115.253"
                )

                // 허용할 HTTP 메서드
                .allowedMethods("*")  // GET, POST, PUT, PATCH, DELETE 등 전체 허용

                // 허용할 HTTP 헤더
                .allowedHeaders("*")  // Content-Type, Authorization 등 전체 허용

                // 인증 정보(쿠키, Authorization 헤더 등) 포함한 요청 허용
                .allowCredentials(true);
    }
}
