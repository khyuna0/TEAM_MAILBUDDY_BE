package com.example.mailbuddy.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.List;

@Component
@RequiredArgsConstructor
public class JwtTokenProvider {

    // ★ 환경변수 또는 yml에서 secret 키 로드해도 됨
    @Value("${jwt.secret:my_jwt_secret_123456789012345678901234}")
    private String secretKeyPlain;

    private SecretKey getSecretKey() {
        return Keys.hmacShaKeyFor(secretKeyPlain.getBytes());
    }

    // ★ access token 유효시간: 2시간
    private final long validityInMs = 1000L * 60 * 60 * 2;

    // ★ 토큰 생성
    public String createToken(String email, List<String> roles) {
        Claims claims = Jwts.claims().setSubject(email);
        claims.put("roles", roles);

        Date now = new Date();
        Date exp = new Date(now.getTime() + validityInMs);

        return Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(now)
                .setExpiration(exp)
                .signWith(getSecretKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    // ★ 토큰에서 인증 정보 추출
    public String getUsername(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSecretKey())
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }

    // ★ 토큰 검증
    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder().setSigningKey(getSecretKey()).build().parseClaimsJws(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }
}
