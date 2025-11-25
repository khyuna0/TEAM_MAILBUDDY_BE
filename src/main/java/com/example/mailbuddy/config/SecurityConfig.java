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
    private OAuth2LoginFailureHandler oauth2LoginFailureHandler;

    @Autowired
    private ClientRegistrationRepository clientRegistrationRepository;

    // =========================
    // 🔥 메인 Security Filter
    // =========================
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http
                .csrf(csrf -> csrf.disable())
                .cors(Customizer.withDefaults())
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                        .requestMatchers(
                                "/", "/index.html",
                                "/login",
                                "/api/auth/**",
                                "/error"
                        ).permitAll()

                        .requestMatchers("/api/admin/**").hasRole("ADMIN")
                        .requestMatchers("/api/user/**").hasRole("USER")

                        .requestMatchers("/api/me/profile").authenticated()
                        .requestMatchers("/api/todo/**").authenticated()
                        .anyRequest().authenticated()
                )
                .formLogin(login -> login
                        .loginPage("/login").permitAll()
                        .loginProcessingUrl("/api/auth/login")
                        .usernameParameter("username")
                        .passwordParameter("password")
                        .successHandler(customLoginSuccessHandler)
                        .failureHandler((req, res, ex) -> res.setStatus(HttpServletResponse.SC_UNAUTHORIZED))
                )
                .oauth2Login(oauth2 -> oauth2
                        .loginPage("/login").permitAll()
                        .authorizationEndpoint(auth -> auth
                                .authorizationRequestResolver(customOAuth2AuthorizationRequestResolver())
                        )
                        .userInfoEndpoint(userInfo -> userInfo
                                .userService(customOAuth2UserService)
                        )
                        .failureHandler(oauth2LoginFailureHandler)
                )
                .logout(logout -> logout
                        .logoutUrl("/api/auth/logout")
                        .invalidateHttpSession(true)
                        .clearAuthentication(true)
                        .deleteCookies("JSESSIONID", "remember-me", "Authorization")
                        .logoutSuccessHandler((req, res, auth) -> res.setStatus(HttpServletResponse.SC_OK))
                )
                .anonymous(anonymous -> anonymous.disable());

        return http.build();
    }

    // =========================
    // 🔥 OAuth2 계정 선택창 강제
    // =========================
    @Bean
    public OAuth2AuthorizationRequestResolver customOAuth2AuthorizationRequestResolver() {

        DefaultOAuth2AuthorizationRequestResolver defaultResolver =
                new DefaultOAuth2AuthorizationRequestResolver(
                        clientRegistrationRepository,
                        "/oauth2/authorization"
                );

        return new OAuth2AuthorizationRequestResolver() {

            @Override
            public OAuth2AuthorizationRequest resolve(jakarta.servlet.http.HttpServletRequest request) {
                OAuth2AuthorizationRequest authorizationRequest = defaultResolver.resolve(request);
                return customize(authorizationRequest);
            }

            @Override
            public OAuth2AuthorizationRequest resolve(jakarta.servlet.http.HttpServletRequest request, String clientRegistrationId) {
                OAuth2AuthorizationRequest authorizationRequest = defaultResolver.resolve(request, clientRegistrationId);
                return customize(authorizationRequest);
            }

            private OAuth2AuthorizationRequest customize(OAuth2AuthorizationRequest authorizationRequest) {
                if (authorizationRequest == null) return null;

                Map<String, Object> params = new HashMap<>(authorizationRequest.getAdditionalParameters());
                params.put("prompt", "select_account");

                return OAuth2AuthorizationRequest.from(authorizationRequest)
                        .additionalParameters(params)
                        .build();
            }
        };
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // =========================
    // 🔥 전역 CORS — 최종 버전
    // =========================
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();

        config.setAllowedOrigins(List.of(
                "http://localhost:3000",
                "http://52.79.115.253",
                "http://52.79.115.253:3000",
                "http://mailbuddy-s3-fe.s3-website-ap-northeast-2.amazonaws.com"
        ));

        config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"));
        config.setAllowedHeaders(List.of("*"));
        config.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);

        return source;
    }
}
