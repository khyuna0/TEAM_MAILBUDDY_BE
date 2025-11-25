package com.example.mailbuddy.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDate;

@Entity
@Getter
@Setter
@JsonIgnoreProperties({"hibernateLazyInitializer", "handler"})
@Builder
@AllArgsConstructor
@NoArgsConstructor
// 필드 순서 다 기억해야 하는 불편을 없애고, 명시적이고 안전한 방식으로 객체를 만들 수 있게 하는 패턴
// 롬복 자동 생성 메서드임
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id; // 유저 고유 키
    @Column(unique = true)
    private String username; // 유저 아이디
    @JsonIgnore // user 엔티티를 불러오는 경우 비밀번호 노출 시키지 않기 위함
    private String password; // 유저 비밀번호
    private String name; // 유저 이름
    private String birth; // 유저 생일
    @Column(unique = true)
    private String googleEmail; // 구글 이메일 연동
    @Enumerated(EnumType.STRING)
    private UserRole userRole;

    @PrePersist // 엔티티가 DB에 INSERT 되기 전에 호출됨
    public void setUserRole() {
        if( this.userRole == null ) {

            if(this.username.equals("admin")) {
                this.userRole = UserRole.ADMIN;
                return;
            }
            this.userRole = UserRole.USER; // 기본 값을 USER 로 설정
        }
    }

}

