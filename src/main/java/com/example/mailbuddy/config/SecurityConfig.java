package com.example.mailbuddy.config;

import com.example.mailbuddy.jwt.JwtAuthenticationFilter;     // ★ 추가: JWT 인증 필터
import com.example.mailbuddy.jwt.JwtTokenProvider;           // ★ 추가: JWT 토큰 생성/검증

import com.example.mailbuddy.handler.OAuth2LoginFailureHandler;
import com.example.mailbuddy.jwt.OAuth2JwtSuccessHandler;
import com.example.mailbuddy.service.CustomOAuth2UserService;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import jakarta.servlet.http.HttpServletResponse;

import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;   // ★ 추가
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;  // ★ JWT 필터 위치 지정용

import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    private final CustomOAuth2UserService customOAuth2UserService;
    private final OAuth2LoginFailureHandler oauth2LoginFailureHandler;
    private final ClientRegistrationRepository clientRegistrationRepository;

    private final JwtTokenProvider jwtTokenProvider;          // ★ 추가
    private final OAuth2JwtSuccessHandler oAuth2JwtSuccessHandler; // ★ 추가

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http.csrf(csrf -> csrf.disable());
        http.cors(cors -> cors.configurationSource(corsConfigurationSource()));

        // ★ 핵심: 세션 완전 제거 → JWT 기반 인증을 위해 STATELESS 설정
        http.sessionManagement(session ->
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        );

        http.authorizeHttpRequests(auth -> auth
                .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                .requestMatchers("/login", "/api/auth/**", "/error").permitAll()
                .requestMatchers("/api/admin/**").hasRole("ADMIN")
                .requestMatchers("/api/user/**").hasRole("USER")
                .anyRequest().authenticated()
        );

        // ★ 기존 formLogin 제거 (세션 기반)
        // http.formLogin(...)  → 완전히 삭제

        // ★ OAuth2 설정은 유지하면서 “성공 시 JWT 발급” 방식으로만 변경
        http.oauth2Login(oauth2 -> oauth2
                .loginPage("/login").permitAll()
                .authorizationEndpoint(authz ->
                        authz.authorizationRequestResolver(customOAuthRequestResolver())
                )
                .userInfoEndpoint(userinfo -> userinfo.userService(customOAuth2UserService))
                .failureHandler(oauth2LoginFailureHandler)
                .successHandler(oAuth2JwtSuccessHandler)
        );

        // ★ 로그아웃도 쿠키/세션 삭제 필요 없으므로 간단하게 처리 가능
        http.logout(logout -> logout
                .logoutUrl("/api/auth/logout")
                .logoutSuccessHandler((req, res, auth) ->
                        res.setStatus(HttpServletResponse.SC_OK))
        );

        // ★ JWT 인증 필터 추가: UsernamePasswordAuthenticationFilter 전에 실행
        http.addFilterBefore(
                new JwtAuthenticationFilter(jwtTokenProvider, userDetailsService),
                UsernamePasswordAuthenticationFilter.class
        );

        // ★ 불필요 → 세션 기반이라 삭제
        // http.anonymous(...), http.sessionIdResolver(...)

        return http.build();
    }

    // OAuth2 인증 요청 커스텀 유지
    @Bean
    public OAuth2AuthorizationRequestResolver customOAuthRequestResolver() {
        DefaultOAuth2AuthorizationRequestResolver defaultResolver =
                new DefaultOAuth2AuthorizationRequestResolver(
                        clientRegistrationRepository, "/oauth2/authorization"
                );

        return new OAuth2AuthorizationRequestResolver() {
            @Override
            public OAuth2AuthorizationRequest resolve(jakarta.servlet.http.HttpServletRequest request) {
                return customize(defaultResolver.resolve(request));
            }

            @Override
            public OAuth2AuthorizationRequest resolve(jakarta.servlet.http.HttpServletRequest request,
                                                      String clientRegistrationId) {
                return customize(defaultResolver.resolve(request, clientRegistrationId));
            }

            private OAuth2AuthorizationRequest customize(OAuth2AuthorizationRequest req) {
                if (req == null) return null;
                Map<String, Object> params = new HashMap<>(req.getAdditionalParameters());
                params.put("prompt", "select_account");
                return OAuth2AuthorizationRequest.from(req)
                        .additionalParameters(params)
                        .build();
            }
        };
    }

    // ★ JWT 기반으로 바꿨으므로 쿠키, 세션 노출 필요 없음
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();

        config.setAllowedOrigins(List.of(
                "http://localhost:3000",
                "http://mailbuddy-s3-fe.s3-website.ap-northeast-2.amazonaws.com"
        ));

        config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"));

        // ★ JWT는 Authorization 헤더 사용 → 헤더 허용 필요
        config.setAllowedHeaders(List.of("Authorization", "Content-Type"));

        config.setExposedHeaders(List.of("Authorization"));   // ★ 프론트에서 jwt 읽도록

        config.setAllowCredentials(false); // ★ JWT는 쿠키를 사용하지 않으므로 false 권장

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);

        return source;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
