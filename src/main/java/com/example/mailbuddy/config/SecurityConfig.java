package com.example.mailbuddy.config;

import com.example.mailbuddy.handler.CustomLoginSuccessHandler;
import com.example.mailbuddy.handler.OAuth2LoginFailureHandler;
import com.example.mailbuddy.service.CustomOAuth2UserService;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.session.web.http.CookieHttpSessionIdResolver;
import org.springframework.session.web.http.DefaultCookieSerializer;
import org.springframework.session.web.http.HttpSessionIdResolver;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Configuration
public class SecurityConfig {

    @Autowired private CustomLoginSuccessHandler customLoginSuccessHandler;
    @Autowired private CustomOAuth2UserService customOAuth2UserService;
    @Autowired private OAuth2LoginFailureHandler oauth2LoginFailureHandler;
    @Autowired private ClientRegistrationRepository clientRegistrationRepository;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http.csrf(csrf -> csrf.disable());
        http.cors(cors -> cors.configurationSource(corsConfigurationSource()));

        http.authorizeHttpRequests(auth -> auth
                .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                .requestMatchers("/login", "/api/auth/**", "/error").permitAll()
                .requestMatchers("/api/admin/**").hasRole("ADMIN")
                .requestMatchers("/api/user/**").hasRole("USER")
                .anyRequest().authenticated()
        );

        // ★ S3 SPA root 로 이동해야 404 안 남
        String S3_FE = "http://mailbuddy-s3-fe.s3-website.ap-northeast-2.amazonaws.com/";

        http.formLogin(login -> login
                .loginPage("/login").permitAll()
                .loginProcessingUrl("/api/auth/login")
                .usernameParameter("username")
                .passwordParameter("password")
                .successHandler(customLoginSuccessHandler)
                .defaultSuccessUrl(S3_FE, true)
                .failureHandler((req, res, ex) -> res.setStatus(HttpServletResponse.SC_UNAUTHORIZED))
        );

        http.oauth2Login(oauth2 -> oauth2
                .loginPage("/login").permitAll()
                .authorizationEndpoint(authz ->
                        authz.authorizationRequestResolver(customOAuthRequestResolver())
                )
                .userInfoEndpoint(userinfo -> userinfo.userService(customOAuth2UserService))
                .failureHandler(oauth2LoginFailureHandler)
                .defaultSuccessUrl(S3_FE, true)
        );

        http.logout(logout -> logout
                .logoutUrl("/api/auth/logout")
                .invalidateHttpSession(true)
                .clearAuthentication(true)
                .deleteCookies("JSESSIONID", "remember-me")
                .logoutSuccessHandler((req, res, auth) ->
                        res.setStatus(HttpServletResponse.SC_OK)
                )
        );

        http.anonymous(anonymous -> anonymous.disable());

        return http.build();
    }

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

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();

        config.setAllowedOrigins(List.of(
                "http://localhost:3000",
                "http://mailbuddy-s3-fe.s3-website.ap-northeast-2.amazonaws.com"
        ));
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"));
        config.setAllowedHeaders(List.of("*"));

        // ★ 리다이렉트(Location) + 세션(Set-Cookie) 둘 다 노출해야 로그인 성공처리됨
        config.setExposedHeaders(List.of("Set-Cookie", "Location"));
        config.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);

        return source;
    }

    @Bean
    public HttpSessionIdResolver httpSessionIdResolver() {
        CookieHttpSessionIdResolver resolver = new CookieHttpSessionIdResolver();
        DefaultCookieSerializer cs = new DefaultCookieSerializer();

        cs.setCookieName("JSESSIONID");
        cs.setSameSite("Lax");
        cs.setUseSecureCookie(false);
        cs.setCookiePath("/");

        resolver.setCookieSerializer(cs);
        return resolver;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
