package com.growmming.gurdening.controller;

import com.growmming.gurdening.domain.dto.TokenDTO;
import com.growmming.gurdening.domain.dto.UserDTO;
import com.growmming.gurdening.service.OAuth2Service;
import jakarta.servlet.http.HttpServletRequest;
import java.security.Principal;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/oauth2")
@RequiredArgsConstructor
public class OAuth2Controller {
    private final OAuth2Service oAuth2Service;

    @ResponseBody
    @GetMapping("/google") // 지정된 URL을 통해 구글 로그인시 구글 토큰을 발급합니다
    public TokenDTO.GoogleToken googleCallback(@RequestParam String code) {
        return oAuth2Service.getGoogleToken(code);
    }

    @PostMapping("/login") // 존재하지 않은 유저일 경우 회원가입 진행 후 로그인합니다
    public ResponseEntity<TokenDTO.ServiceToken> login(@RequestBody UserDTO.RequestLogin dto) {
        TokenDTO.ServiceToken serviceToken = oAuth2Service.joinAndLogin(dto);
        return ResponseEntity.ok(serviceToken);
    }

    @PostMapping("/refresh") // 리프레시 토큰을 통해 엑세스 토큰 유효 기간 초기화
    public ResponseEntity<TokenDTO.ServiceToken> refresh(HttpServletRequest request, @RequestBody TokenDTO.ServiceToken dto) {
        TokenDTO.ServiceToken serviceToken = oAuth2Service.refresh(request, dto);
        return ResponseEntity.ok(serviceToken);
    }

    @PostMapping("/logout") // 액세스 토큰 블랙리스트에 저장 및 리프레시 토큰 제거
    public ResponseEntity<String> logout(HttpServletRequest request, @RequestBody TokenDTO.ServiceToken dto, Principal principal) {
        oAuth2Service.logout(request, dto, principal);
        return ResponseEntity.ok("로그아웃 완료");
    }
}
