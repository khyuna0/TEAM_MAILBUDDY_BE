package com.example.mailbuddy.controller;

import com.example.mailbuddy.dto.MypageResponseDto;
import com.example.mailbuddy.dto.UpdateProfileRequest;
import com.example.mailbuddy.dto.UserRequestDto;
import com.example.mailbuddy.entity.User;
import com.example.mailbuddy.repository.UserRepository;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.validation.BindingResult;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDate;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
// 회원가입 + 마이페이지
public class AuthController {

    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private UserRepository userRepository;

    // 회원가입
    @PostMapping("/signup")
    public ResponseEntity<?> signup(@RequestBody @Valid UserRequestDto req, BindingResult result) {
        Map<String, String> errors = new HashMap<>();
        if (userRepository.findByUsername(req.getUsername()).isPresent()) { // 아이디 중복 여부 검사
            errors.put("idError", "이미 존재하는 아이디입니다.");
        }
        if (result.hasErrors()) {
            result.getFieldErrors().forEach(err -> {
                        errors.put(err.getField(), err.getDefaultMessage());
                    }
            );
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

    // 현재 폼로그인한 유저의 username + 생일 + userRole 가져오기 (jsessionid 이용)
//    @GetMapping("/me")
//    public ResponseEntity<?> getCurrentUser(Authentication authentication) {
//        if (authentication == null || !authentication.isAuthenticated()) {
//            return ResponseEntity.status(HttpServletResponse.SC_UNAUTHORIZED)
//                    .body(Map.of("error", "로그인되지 않음"));
//        }
//        User user = userRepository.findByUsername(authentication.getName()).orElseThrow(
//                () -> new UsernameNotFoundException("username not found: " + authentication.getName())
//        );
//
//        if (user == null) {
//            return ResponseEntity.ok(Map.of("authenticated", false));
//        }
////        System.out.println(user.getUserRole().name());
//        return ResponseEntity.ok(Map.of(
//                "authenticated", true,
//                "username", user.getUsername(),
//                "birth", user.getBirth(),
//                "userRole", user.getUserRole().name()
//        ));
//        // 결과 { "birth": "2025-11-05", "username": "ccc" , "userRole" : "ADMIN" or "USER" }
//    }


    // 현재 폼+구글 로그인한 유저의 username + 구글 이메일 가져오기 (jsessionid 이용)
    @GetMapping("/me2")
    public ResponseEntity<?> getCurrentUserOAuth2(OAuth2AuthenticationToken authentication) {
        if (authentication == null || !authentication.isAuthenticated()) {
            return ResponseEntity.status(HttpServletResponse.SC_UNAUTHORIZED)
                    .body(Map.of("error", "구글 로그인되지 않음"));
        }
        OAuth2User user = authentication.getPrincipal();
        String username = authentication.getName();
        String email = user.getAttribute("email"); // 구글 이메일
        return ResponseEntity.ok(Map.of("username", username, "email", email));
    }

    // 로그인한 유저의 username, name, birth .. 등 정보 가져오기 - 마이페이지 수정 (jsessionid 이용)
    @GetMapping("/me")
    public ResponseEntity<?> getCurrentUserInfo(Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated()) {
            return ResponseEntity.status(HttpServletResponse.SC_UNAUTHORIZED)
                    .body(Map.of("error", "로그인되지 않음"));
        }
        User user = userRepository.findByUsername(authentication.getName()).orElseThrow(
                () -> new UsernameNotFoundException("username not found: " + authentication.getName())
        );
        return ResponseEntity.ok(new MypageResponseDto(user.getUsername(), user.getName(), user.getBirth(), user.getUserRole().name()));
        // 결과 { "username": "ccc", "name": "김민지", "birth": "2025-11-05", "userRole": "" }
    }

    // 마이페이지 수정
    @PatchMapping("/profile")
    public ResponseEntity<?> updateProfile(@Validated(UpdateProfileRequest.ValidationSequence.class) @RequestBody UpdateProfileRequest req,
                                           BindingResult result, Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated()) {
            return ResponseEntity.status(HttpServletResponse.SC_UNAUTHORIZED)
                    .body(Map.of("error", "로그인되지 않음"));
        }
        // 검증 에러 있으면 400으로 메시지 반환
        if (result.hasErrors()) {
            Map<String, String> errors = new HashMap<>();
            result.getFieldErrors().forEach(err ->
                    errors.put(err.getField(), err.getDefaultMessage())
            );
            return ResponseEntity.badRequest().body(errors);
        }
        User user = userRepository.findByUsername(authentication.getName()).orElseThrow(
                () -> new UsernameNotFoundException("username not found: " + authentication.getName())
        );
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
        return ResponseEntity.ok(new MypageResponseDto(user.getUsername(), user.getName(), user.getBirth()));
    }


}
