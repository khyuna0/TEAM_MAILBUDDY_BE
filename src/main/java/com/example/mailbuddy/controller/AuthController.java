package com.example.mailbuddy.controller;

import com.example.mailbuddy.dto.MypageResponseDto;
import com.example.mailbuddy.dto.UpdateProfileRequest;
import com.example.mailbuddy.dto.UserRequestDto;
import com.example.mailbuddy.entity.User;
import com.example.mailbuddy.jwt.JwtTokenProvider;   // ★ 추가
import com.example.mailbuddy.repository.UserRepository;

import jakarta.validation.Valid;

import lombok.RequiredArgsConstructor;

import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;                  // ★ 추가
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken; // ★ 추가
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;

import org.springframework.validation.BindingResult;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;

    // ★ JWT 로그인용
    private final AuthenticationManager authenticationManager;

    // ★ JWT 생성기
    private final JwtTokenProvider jwtTokenProvider;

    // ==========================================
    // 회원가입
    // ==========================================
    @PostMapping("/signup")
    public ResponseEntity<?> signup(@RequestBody @Valid UserRequestDto req, BindingResult result) {
        Map<String, String> errors = new HashMap<>();

        if (userRepository.findByUsername(req.getUsername()).isPresent()) {
            errors.put("idError", "이미 존재하는 아이디입니다.");
        }

        if (result.hasErrors()) {
            result.getFieldErrors().forEach(err -> {
                errors.put(err.getField(), err.getDefaultMessage());
            });
        }

        if (!errors.isEmpty()) {
            return ResponseEntity.badRequest().body(errors);
        }

        User user = new User();
        user.setUsername(req.getUsername());
        user.setPassword(passwordEncoder.encode(req.getPassword()));
        user.setName(req.getName());
        user.setBirth(req.getBirth());
        userRepository.save(user);

        return ResponseEntity.ok().body("가입 완료");
    }

    // ==========================================
    // ★★★ JWT 로그인 (새로운 로그인 API)
    // ==========================================
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Map<String, String> body) {

        String username = body.get("username");
        String password = body.get("password");

        // 1) 스프링 시큐리티 인증 (DB 조회 + 패스워드 검사)
        Authentication auth = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(username, password)
        );

        // 2) JWT 생성
        String token = jwtTokenProvider.createToken(
                auth.getName(),     // username
                auth.getAuthorities().stream()
                        .map(a -> a.getAuthority())
                        .toList()
        );

        // 3) 프론트에서 localStorage 저장하도록 key 전달
        return ResponseEntity.ok(Map.of("accessToken", token));
    }

    // ==========================================
    // ★ JWT 기반 현재 사용자 정보 조회
    // ==========================================
    @GetMapping("/me")
    public ResponseEntity<?> getCurrentUserInfo(Authentication authentication) {

        // ★ JWT 인증 시 authentication != null 상태 유지됨
        if (authentication == null || !authentication.isAuthenticated()) {
            return ResponseEntity.status(401).body(Map.of("error", "로그인되지 않음"));
        }

        User user = userRepository.findByUsername(authentication.getName())
                .orElseThrow(() ->
                        new UsernameNotFoundException("username not found: " + authentication.getName())
                );

        return ResponseEntity.ok(
                new MypageResponseDto(
                        user.getUsername(),
                        user.getName(),
                        user.getBirth(),
                        user.getUserRole().name()
                )
        );
    }

    // ==========================================
    // ★ JWT 기반 마이페이지 수정
    // ==========================================
    @PatchMapping("/profile")
    public ResponseEntity<?> updateProfile(
            @Validated(UpdateProfileRequest.ValidationSequence.class) @RequestBody UpdateProfileRequest req,
            BindingResult result,
            Authentication authentication
    ) {
        if (authentication == null || !authentication.isAuthenticated()) {
            return ResponseEntity.status(401).body(Map.of("error", "로그인되지 않음"));
        }

        if (result.hasErrors()) {
            Map<String, String> errors = new HashMap<>();
            result.getFieldErrors().forEach(err -> {
                errors.put(err.getField(), err.getDefaultMessage());
            });
            return ResponseEntity.badRequest().body(errors);
        }

        User user = userRepository.findByUsername(authentication.getName())
                .orElseThrow(() -> new UsernameNotFoundException("username not found"));

        // 이름
        if (req.getName() != null && !req.getName().trim().isEmpty()) {
            user.setName(req.getName().trim());
        }

        // 생일
        if (req.getBirth() != null) {
            user.setBirth(req.getBirth());
        }

        // 비밀번호
        if (req.getPassword() != null && !req.getPassword().trim().isEmpty()) {
            user.setPassword(passwordEncoder.encode(req.getPassword().trim()));
        }

        userRepository.save(user);

        return ResponseEntity.ok(
                new MypageResponseDto(
                        user.getUsername(),
                        user.getName(),
                        user.getBirth()
                )
        );
    }
}
