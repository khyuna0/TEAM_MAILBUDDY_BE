package com.example.mailbuddy.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebMvcConfig implements WebMvcConfigurer {

    @Override
    public void addCorsMappings(CorsRegistry registry) {

        registry.addMapping("/**")
                .allowedOrigins(
                        "http://localhost:3000",  // 로컬 개발
                        "http://52.79.115.253",   // EC2 프론트엔드
                        "http://mailbuddy-s3-fe.s3-website-ap-northeast-2.amazonaws.com" // S3 정적 사이트
                )
                .allowedMethods("*")        // GET/POST/PUT/PATCH/DELETE 모두 허용
                .allowedHeaders("*")        // 모든 헤더 허용
                .allowCredentials(true);    // 쿠키, 인증 헤더 허용
    }
}
