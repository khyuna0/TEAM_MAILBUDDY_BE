package com.example.mailbuddy.controller;

import com.example.mailbuddy.utils.EmailTimeParser;
import com.example.mailbuddy.entity.Gmail;
import com.example.mailbuddy.entity.User;
import com.example.mailbuddy.repository.GmailRepository;
import com.example.mailbuddy.repository.UserRepository;
import com.example.mailbuddy.service.GmailService;
import com.example.mailbuddy.service.UserSecurityService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.WebClient;

import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.List;

@RestController
@RequestMapping("/api/gmail")
public class GmailController {

    @Autowired
    private UserRepository userRepository;
    @Autowired
    private UserSecurityService userSecurityService;
    @Autowired
    private GmailService gmailService;
    @Autowired
    private GmailRepository gmailRepository;
    @Autowired
    @Qualifier("gmailWebClient")
    private WebClient gmailWebClient;

    // 인증된 사용자 정보의 이름과 이메일 주소 가져오기 (백엔드 확인용)
    @GetMapping("/userInfo")
    public ResponseEntity<String> getGoogleUser(OAuth2AuthenticationToken authentication) {
        OAuth2User user = authentication.getPrincipal();
        String email = user.getAttribute("email"); // 사용자 이메일 가져오기
        String name = user.getAttribute("name");   // 사용자 이름 가져오기 (있으면)
        String userInfo = "[사용자 이름] " + name + " [사용자 구글 이메일] " + email;
        return ResponseEntity.ok().body(userInfo);
    }

    // 사용자의 메일 목록 가져오기 (최대 100개인듯) [{id : ""}, {threadId : ""}] 로 이루어져 있음. id 안에 모든 정보 저장되어 있음
    @GetMapping("/messages")
    // OAuth2AuthenticationToken 은 스프링 시큐리티에서 OAuth2 인증 토큰을 표현하는 객체로, 로그인된 OAuth2 사용자의 상태를 알려줌
    public ResponseEntity<String> getMessages(OAuth2AuthenticationToken authentication) {
        String accessToken = gmailService.getUserToken(authentication);
        String mailListResponse = gmailWebClient.get()
                .uri("/users/me/messages")  // gmailWebClient baseUrl 뒤에 붙는 부분
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)  // 토큰을 여기서 추가
                .retrieve() // 응답 수신
                .bodyToMono(String.class) // 응답 바디를 원하는 타입으로 변환
                .block(); // 동기식 반환
        return ResponseEntity.ok(mailListResponse);
    }

    // 사용자의 상위 최신 이메일 10개 가져오기 + 엔티티 저장 + 중복방지 처리
    @GetMapping("/messages/save-top10")
    public ResponseEntity<String> saveTop10Messages(OAuth2AuthenticationToken authentication) {
        // 인증된 사용자의 구글 아이디를 통해서 사용자 엔티티 가져오기
        User user = userSecurityService.getUserfindByGoogleEmail(authentication);
        // 토큰 ->  authentication헤더에 넣어서 Gmail API에 요청
        String accessToken = gmailService.getUserToken(authentication);
        // 1. 상위 10개 메일 리스트 (id, threadid, nextpagetoken .. 추출)
        int top10 = 10;
        String mailListTop10Response = gmailWebClient.get()
                .uri(uriBuilder -> uriBuilder
                        .path("/users/me/messages") //Gmail API의 메세지목록 엔드포인트
                        .queryParam("maxResults", top10) //maxResult = 10 쿼리파라미터
                        .build())
                //HTTP 헤더에 Authorization: Bearer 액세스토큰 넣어서 사용자 메일 접근 권한 증명
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
                //응답 받음 -> 문자열(JSON텍스트)꺼냄 -> block()으로 동기 방식으로 결과 기다림
                .retrieve()
                .bodyToMono(String.class)
                .block();
        //JSON 파싱해서 메세지 배열 꺼내기
        try {
            //new JSONObject(..) -> 문자열을 JSON객체로 바꿈
            org.json.JSONObject listJson = new org.json.JSONObject(mailListTop10Response);
            //optJSONArray("messages") -> {"messages":[{id:..},{id:..},...]} 구조에서 "messages"라는 키 해당 배열 꺼냄
            org.json.JSONArray messagesArray = listJson.optJSONArray("messages");
            if (messagesArray == null || messagesArray.isEmpty()) {
                return ResponseEntity.ok("저장할 메시지가 없습니다.");
            }

            // saved : 성공적으로 저장된 메일 개수
            int saved = 0;
            // 2. 각각 메시지 ID별 상세 정보 요청 및 저장
            for (int i = 0; i < messagesArray.length(); i++) {
                //getJSONObject(i).getString("id") -> 각메일에서 "id"값 꺼냄(Gmail 고유 ID) -> 중복막기위해
                String messageId = messagesArray.getJSONObject(i).getString("id");
                //gmail 중복이면 건너뛰기
                //gmail에서 해당사용자 + 해당 messageId로 저장된 메일 있는지 확인
                if (gmailRepository.existsByUserAndMessageId(user, messageId)) {
                    continue; //더이상 처리하지 않고 반복 건너뛰기
                }
                //Gmail API로 각 메일의 상세내용 가져오기
                //API주소로 상세정보 가져옴 -> 헤더에 토큰넣기 -> 응답을 JSON텍스트로 받아서 detailResponse에 저장
                String detailResponse = gmailWebClient.get()
                        .uri("/users/me/messages/" + messageId)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
                        .retrieve()
                        .bodyToMono(String.class)
                        .block();

                //상세 JSON에서 payload / headers 꺼내기
                //new JSONObject(detailResponse) -> 상세응답(JSON 문자열)을 JSON객체로 바꿈
                org.json.JSONObject json = new org.json.JSONObject(detailResponse);
                org.json.JSONObject payload = json.getJSONObject("payload");

                // 헤더 추출 및 파싱(이전 코드 재활용)
                // 나중에 보낸사람,날짜,제목 여기 담기 위해 일단 빈문자열로 초기화
                String from = "";
                String date = "";
                String subject = "";
                //payload.getJSONArray("headers") -> 여러헤더정보(From,To,Subject,..) 들어있는 배열
                org.json.JSONArray headers = payload.getJSONArray("headers");
                //헤더배열에서 From / Date / Subject 찾기
                for (int j = 0; j < headers.length(); j++) {
                    org.json.JSONObject header = headers.getJSONObject(j);
                    // 헤더이름 (ex: from, to , subject, date,...)
                    String name = header.getString("name");
                    // 헤더의 실제 값
                    String value = header.getString("value");
                    //"From".equalsIgnoreCase(name) -> 이름이 From이면 from변수에 저장
                    if ("From".equalsIgnoreCase(name)) {
                        from = value;
                    } else if ("Date".equalsIgnoreCase(name)) {
                        date = value;
                    } else if ("Subject".equalsIgnoreCase(name)) {
                        subject = value;
                    }
                }
                //From 헤더에서 이름/이메일주소 분리
                String senderName = "";
                String senderEmail = "";
                if (!from.isEmpty()) {
                    // '<' 의 문자 위치 찾기
                    int startIdx = from.indexOf("<");
                    int endIdx = from.indexOf(">");
                    if (startIdx != -1 && endIdx != -1 && endIdx > startIdx) {
                        // < 앞부분 = 이름부분 , 양쪽 공백제거, ""도 제거
                        senderName = from.substring(0, startIdx).trim().replace("\"", "");
                        // < , > 사이 = 이메일 주소 부분
                        senderEmail = from.substring(startIdx + 1, endIdx).trim();
                    } else {
                        // <,> 없다면 -> 전체 문자열 이메일로 보고 그대로 넣기
                        senderEmail = from.trim();
                    }
                }

                // 본문 추출 (이전 코드 재활용)
                String data = "";
                if (payload.has("body") && payload.getJSONObject("body").has("data")) {
                    data = payload.getJSONObject("body").optString("data", "");
                }
                if (data.isEmpty() && payload.has("parts")) {
                    org.json.JSONArray parts = payload.getJSONArray("parts");
                    for (int k = 0; k < parts.length(); k++) {
                        org.json.JSONObject part = parts.getJSONObject(k);
                        String mimeType = part.getString("mimeType");
                        if ("text/html".equalsIgnoreCase(mimeType) || "text/plain".equalsIgnoreCase(mimeType)) {
                            data = part.getJSONObject("body").optString("data", "");
                            if (!data.isEmpty()) break;
                        }
                    }
                }
                String bodyContent = "";
                if (!data.isEmpty()) {
                    byte[] decodedBytes = Base64.getUrlDecoder().decode(data);
                    bodyContent = new String(decodedBytes, StandardCharsets.UTF_8);
                    // 본문 길이 제한: DB 컬럼 최대 길이에 맞게 자르기
                    int maxBytes = 65535;  // TEXT 한계
                    if (decodedBytes.length > maxBytes) {
                        // UTF-8 바이트 기준 자르기 - 안전한 방법(복잡할 수 있음)
                        // 여기선 최대 바이트까지만 자를 수 있도록 적절히 자르는 라이브러리 사용 권장
                        // 간단히 4000글자 정도로 제한 (안전한 넉넉한 여유)
                        int maxChars = 500;
                        if (bodyContent.length() > maxChars) {
                            bodyContent = bodyContent.substring(0, maxChars) + "...";
                        }
                    }
                }

                // 날짜 변환 메서드 이용
                LocalDateTime koreanReceiveTime = EmailTimeParser.parseReceivedTime(date);

                // 저장 (messageId + user 포함)
                Gmail gmail = new Gmail(
                        messageId,
                        senderName, senderEmail,
                        koreanReceiveTime,
                        subject,
                        bodyContent,
                        user
                );
                gmailRepository.save(gmail);
                saved++;
            }
            return ResponseEntity.ok(saved + "개 메일을 DB에 저장 완료했습니다.");
        } catch (Exception e) {
            return ResponseEntity.status(500).body("메일 저장 중 오류 발생: " + e.getMessage());
        }
    }

    // db에 저장된 모든 메일 목록 조회
    @GetMapping("/get/all")
    public ResponseEntity<List<Gmail>> getAllEmails() {
        List<Gmail> emails = gmailRepository.findAll();
        return ResponseEntity.ok(emails);
    }

    // 해당 사용자의 db에 저장된 메일 목록 조회
    @GetMapping("/get/usermails")
    public ResponseEntity<List<Gmail>> getEmails(OAuth2AuthenticationToken authentication) {
        OAuth2User user = authentication.getPrincipal();
        String email = user.getAttribute("email");
        User loginUser = userRepository.findByGoogleEmail(email).orElseThrow(() ->
                new UsernameNotFoundException("User not found: "));
        List<Gmail> emails = gmailRepository.findByUser(loginUser); // user_id 맞게 가져오기
        return ResponseEntity.ok(emails);
    }
}
