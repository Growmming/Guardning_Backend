package com.growmming.gurdening.controller;

import com.growmming.gurdening.domain.dto.MemberDTO;
import com.growmming.gurdening.domain.dto.TokenDTO;
import com.growmming.gurdening.service.OAuth2Service;
import jakarta.servlet.http.HttpServletRequest;
import java.security.Principal;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class OAuth2Controller {
    private final OAuth2Service oAuth2Service;

    @PostMapping("/api/oauth2/callback/google")
    public TokenDTO.GoogleToken googleCallback(@RequestParam(name = "code") String code) {
        return oAuth2Service.getGoogleAccessToken(code);
    }

    @PostMapping("/oauth2/login")
    public ResponseEntity<TokenDTO.ServiceToken> loginOrSignUp(@RequestBody MemberDTO.RequestLogin dto) {
        TokenDTO.ServiceToken serviceToken = oAuth2Service.loginOrSignUp(dto);
        return ResponseEntity.ok(serviceToken);
    }

    @PostMapping("/oauth2/refresh")
    public ResponseEntity<TokenDTO.ServiceToken> refresh(HttpServletRequest request, @RequestBody TokenDTO.ServiceToken dto) {
        TokenDTO.ServiceToken serviceToken = oAuth2Service.refresh(request, dto);
        return ResponseEntity.ok(serviceToken);
    }

    @PostMapping("/oauth2/logout")
    public ResponseEntity<String> logout(HttpServletRequest request, @RequestBody TokenDTO.ServiceToken dto, Principal principal) {
        oAuth2Service.logout(request, dto, principal);
        return ResponseEntity.ok("로그아웃 완료");
    }

}
