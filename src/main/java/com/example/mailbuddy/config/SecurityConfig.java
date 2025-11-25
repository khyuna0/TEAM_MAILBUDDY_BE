package com.example.mailbuddy.config;

import com.example.mailbuddy.handler.CustomLoginSuccessHandler;
import com.example.mailbuddy.handler.OAuth2LoginFailureHandler;
import com.example.mailbuddy.service.CustomOAuth2UserService;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;


import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Configuration
public class SecurityConfig {

    @Autowired
    private CustomLoginSuccessHandler customLoginSuccessHandler;
    @Autowired
    private CustomOAuth2UserService customOAuth2UserService;
    @Autowired
    private OAuth2LoginFailureHandler oauth2LoginFailureHandler;  // 구글 중복 연동 에러처리
    @Autowired
    private ClientRegistrationRepository clientRegistrationRepository; // 중복 시도 후 다른 구글 아이디 연동시

    // 스프링 시큐리티에서 웹 보안 필터 체인(SecurityFilterChain)을 설정하는 핵심 코드
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                // CSRF 공격 방지 비활성화. 보통 API 서버에서 토큰으로 인증하기 때문에 비활성화하는 경우가 많음
                .csrf(csrf -> csrf.disable())
                // 아래 만든 corsConfigurationSource() 설정을 통해 CORS 정책을 적용
                .cors(Customizer.withDefaults())
                // 요청 권한 설정
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()

                        .requestMatchers(HttpMethod.GET, "/api/me/profile").authenticated()
                        .requestMatchers(HttpMethod.PATCH, "/api/me/profile").authenticated()
                        .requestMatchers(
                                "/**", "/index.html", "/",
                                "/login",       // 로그인 페이지
                                "/api/auth/**",
                                "/api/auth/login",           // 로그인 처리
                                "/api/auth/signup",           // 회원가입
                                "/error"
                        ).permitAll()

                        //여기서 권한 분리
                        .requestMatchers("/api/admin/**").hasRole("ADMIN")
                        .requestMatchers("/api/user/**").hasRole("USER")

                        .requestMatchers("/api/auth/me").authenticated()
                        .requestMatchers("/api/todo/**").authenticated()
                        .anyRequest().authenticated()
                )
                .formLogin(login -> login
                                // 로그인 페이지 경로 지정
                                .loginPage("/login").permitAll()
                                // 로그인 처리 URL 지정
                                .loginProcessingUrl("/api/auth/login")
                                .usernameParameter("username")
                                .passwordParameter("password")
                                .defaultSuccessUrl("http://52.79.115.253:3000/schedule", true)  // 로그인 성공 시 이동할 페이지
//                        .successHandler((req, res, auth) -> res.setStatus(HttpServletResponse.SC_OK))
                                .successHandler(customLoginSuccessHandler)  // 커스텀 로그인 성공 핸들러 등록 **
                                .failureHandler((req, res, ex) -> res.setStatus(HttpServletResponse.SC_UNAUTHORIZED))
                )
                .oauth2Login(oauth2 -> oauth2
                        .loginPage("/login").permitAll()
                        // authorize 요청에 prompt=select_account 붙이기 (항상 계정 선택창 띄우기)
                        .authorizationEndpoint(auth -> auth
                                .authorizationRequestResolver(customOAuth2AuthorizationRequestResolver())
                        )
                        // OAuth2 로그인 성공 후 사용자 정보를 커스텀 서비스로 처리 **
                        .userInfoEndpoint(userInfo -> userInfo
                                .userService(customOAuth2UserService)
                        )
                        .failureHandler(oauth2LoginFailureHandler)
                        .defaultSuccessUrl("http://52.79.115.253:3000/schedule", true)  // 로그인 성공 시 이동할 페이지
                )
                .logout(logout -> logout
                        .logoutUrl("/api/auth/logout")
                        .invalidateHttpSession(true)  // 세션 무효화
                        .clearAuthentication(true)    // 인증 정보 완전 삭제
                        .deleteCookies("JSESSIONID", "remember-me", "auth_code", "Authorization")  // 쿠키 삭제
                        .logoutSuccessHandler((req, res, auth) -> res.setStatus(HttpServletResponse.SC_OK))
                )
                // 인증되지 않은 익명 사용자 차단
                .anonymous(anonymous -> anonymous.disable());
        return http.build();
    }

    // OAuth2 Authorization Request를 커스터마이징 -> prompt=select_account 추가
    // 구글 로그인 시 항상 계정 선택창 띄워주기 (중복 에러 후 다른 아이디 로그인할 때 사용)
    @Bean
    public OAuth2AuthorizationRequestResolver customOAuth2AuthorizationRequestResolver() {
        //반환 타입: OAuth2AuthorizationRequestResolver 인터페이스를 구현한 객체 하나를 리턴하겠다.
        //메서드 이름: customOAuth2AuthorizationRequestResolver -> SecurityConfig 안에서 이이름으로 호출해서 사용.

        // 스프링 시큐리티 기본 resolver
        DefaultOAuth2AuthorizationRequestResolver defaultResolver =
                new DefaultOAuth2AuthorizationRequestResolver(
                        clientRegistrationRepository, //spring.security.oauth2.client.registration.google.* 정보 갖고 있는 빈
                        "/oauth2/authorization" //엔드포인트 prefix(앞부분) -> /oauth2/authorization/google 같은 경로에 대응
                );

        //OAuth2AuthorizationRequestResolver 인터페이스를 익명 클래스 anonymous class로 구현
        // 이 인터페이스는 resolve(...) 메서드가 2개 있어서람다( request -> {} 방식 )로는 구현이 안 됨
        // 그래서 { ... } 안에 두 메서드를 오버라이드해서 구현.
        return new OAuth2AuthorizationRequestResolver() {

            // 1. 기본 resolve(HttpServletRequest) - 파라미터 하나
            @Override
            public OAuth2AuthorizationRequest resolve(jakarta.servlet.http.HttpServletRequest request) {
                OAuth2AuthorizationRequest authorizationRequest = defaultResolver.resolve(request);
                return customize(authorizationRequest);
            }

            // 2. resolve(HttpServletRequest, String clientRegistrationId) - clientRegistrationId 포함
            @Override
            public OAuth2AuthorizationRequest resolve(jakarta.servlet.http.HttpServletRequest request,
                                                      String clientRegistrationId) {
                OAuth2AuthorizationRequest authorizationRequest =
                        defaultResolver.resolve(request, clientRegistrationId);
                return customize(authorizationRequest);
            } // 두 메서드 모두 마지막에 하는 일은 같음 -> 중복 코드를 줄이려고 customize(...)

            // 공통 커스터마이징 로직: prompt=select_account 추가
            private OAuth2AuthorizationRequest customize(OAuth2AuthorizationRequest authorizationRequest) {
                if (authorizationRequest == null) {
                    return null;
                }
                // 기존 파라미터 복사
                // AuthorizationRequest 안에는 additionalParameters 라는 Map있음
                Map<String, Object> additionalParameters =
                        new HashMap<>(authorizationRequest.getAdditionalParameters());
                additionalParameters.put("prompt", "select_account");

                //새로운 AuthorizationRequest로 재빌드
                return OAuth2AuthorizationRequest.from(authorizationRequest)
                        .additionalParameters(additionalParameters)
                        .build();
            }
        };
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // 스프링 시큐리티에서 CORS(Cross-Origin Resource Sharing) 정책을 설정하는 코드
    // 스프링 시큐리티와 스프링 웹에서 "http://localhost:3000"에서 오는 다양한 HTTP 요청이 보안 정책(CORS) 때문에 막히지 않고 정상적으로 통과할 수 있도록 해주는 설정
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(List.of(
                "http://localhost:3000",
                "http://52.79.115.253",
                "http://52.79.115.253:3000",
                "http://mailbuddy-s3-fe.s3-website.ap-northeast-2.amazonaws.com")); // React
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"));
        // 프런트가 보낼 수 있는 헤더 (후자가 모두 허용이라 이전 행에 덮어 씌워짐)
        config.setAllowedHeaders(List.of("Authorization", "Content-Type", "X-Requested-With"));
        config.setAllowedHeaders(List.of("*"));
        config.setAllowCredentials(true);
        // 이 설정을 / 경로 이하 모든 요청에 적용하도록 등록하고 반환
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }
}


