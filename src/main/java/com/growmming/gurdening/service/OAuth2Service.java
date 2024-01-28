package com.growmming.gurdening.service;

import static com.growmming.gurdening.util.ErrorCode.*;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import com.growmming.gurdening.domain.Member;
import com.growmming.gurdening.domain.dto.TokenDTO;
import com.growmming.gurdening.domain.dto.UserDTO;
import com.growmming.gurdening.repository.MemberRepository;
import com.growmming.gurdening.token.TokenProvider;
import com.growmming.gurdening.util.CustomException;
import jakarta.servlet.http.HttpServletRequest;
import java.security.Principal;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.ObjectUtils;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.client.RestTemplate;

@Service
@RequiredArgsConstructor
public class OAuth2Service {
    private final MemberRepository memberRepository;
    private final TokenProvider tokenProvider;
    private final RedisTemplate<String, Object> redisTemplate;
    private final String GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token";
    private final String GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v2/userinfo";
    @Value("${google.client-id}")
    private String GOOGLE_CLIENT_ID;
    @Value("${google.client-secret}")
    private String GOOGLE_CLIENT_SECRET;
    @Value("${google.redirect-uri}")
    private String GOOGLE_REDIRECT_URL;

    public TokenDTO.GoogleToken getGoogleToken(String code) {
        RestTemplate restTemplate = new RestTemplate();
        MultiValueMap<String, String> requestParams = new LinkedMultiValueMap<>();
        requestParams.add("code", code);
        requestParams.add("client_id", GOOGLE_CLIENT_ID);
        requestParams.add("client_secret", GOOGLE_CLIENT_SECRET);
        requestParams.add("redirect_uri", GOOGLE_REDIRECT_URL);
        requestParams.add("grant_type", "authorization_code");

        HttpHeaders headers = new HttpHeaders();
        headers.add("Content-Type", "application/x-www-form-urlencoded;charset=utf-8");

        HttpEntity<MultiValueMap<String, String>> requestEntity = new HttpEntity<>(requestParams, headers);
        ResponseEntity<String> responseEntity = restTemplate.exchange(GOOGLE_TOKEN_URL, HttpMethod.POST, requestEntity,
                String.class);

        if (!responseEntity.getStatusCode().is2xxSuccessful()) {
            throw new CustomException(INVALID_GOOGLE_VALUE);
        }

        JsonElement element = JsonParser.parseString(Objects.requireNonNull(responseEntity.getBody()))
                .getAsJsonObject();
        String accessToken = element.getAsJsonObject().get("access_token").getAsString();
        String refreshToken = element.getAsJsonObject().get("refresh_token").getAsString();

        return new TokenDTO.GoogleToken(accessToken, refreshToken);
    }


    @Transactional
    public TokenDTO.ServiceToken joinAndLogin(UserDTO.RequestLogin dto) {
        // RestTemplate 객체 생성
        RestTemplate restTemplate = new RestTemplate();

        // 헤더 설정, accessToken 전송
        HttpHeaders headers = new HttpHeaders();
        headers.add("Content-Type", "application/x-www-form-urlencoded;charset=utf-8");
        headers.set("Authorization", "Bearer " + dto.getGoogleToken());

        // HttpEntity 생성, 헤더 포함
        HttpEntity<String> requestEntity = new HttpEntity<>(headers);

        // RestTemplate을 이용해 요청을 수행하고 응답을 받음
        ResponseEntity<String> responseEntity = restTemplate.exchange(GOOGLE_USERINFO_URL, HttpMethod.POST,
                requestEntity, String.class);

        // 이메일을 담을 변수 선언
        String email = "";

        // 성공적인 응답인 경우
        if (!responseEntity.getStatusCode().is2xxSuccessful()) {
            throw new CustomException(INVALID_GOOGLE_VALUE);
        }

        // 응답 본문(JSON)을 파싱하기 위한 JsonElement 객체 생성
        JsonElement element = JsonParser.parseString(Objects.requireNonNull(responseEntity.getBody()))
                .getAsJsonObject();

        // 이메일 추출, 카카오 계정 내에 이메일을 가지고 있지 않은 경우 예외 발생
        boolean hasEmail = element.getAsJsonObject().get("google_account").getAsJsonObject().get("has_email")
                .getAsBoolean();
        if (!hasEmail) {
            throw new CustomException(EMAIL_NOT_FOUND);
        }
        email = element.getAsJsonObject().get("google_account").getAsJsonObject().get("email").getAsString();

        // 카카오 로그인을 한 유저가 처음 왔다면 회원가입
        if (memberRepository.findByEmail(email).isEmpty()) {
            Member member = new Member(email);
            memberRepository.save(member);
        }

        // 토큰 발급
        TokenDTO.ServiceToken tokenDTO = tokenProvider.createToken(email);

        // refreshToken의 유효기간
        Long expiration = tokenProvider.getExpiration(tokenDTO.getRefreshToken());

        // refreshToken을 redis에 저장 후 유효성 검증에 사용
        redisTemplate.opsForValue().set(tokenDTO.getRefreshToken(), "refreshToken", expiration, TimeUnit.MILLISECONDS);

        return tokenDTO;
    }


    // 리프레시
    public TokenDTO.ServiceToken refresh(HttpServletRequest request, TokenDTO.ServiceToken dto) {
        String refreshToken = dto.getRefreshToken();

        // refreshToken이 유효하지 않은 경우 예외 발생
        String isValidate = (String) redisTemplate.opsForValue().get(refreshToken);
        if (ObjectUtils.isEmpty(isValidate)) {
            throw new CustomException(INVALID_REFRESH_TOKEN);
        }

        // AccessToken 재발급
        return tokenProvider.createAccessTokenByRefreshToken(request, refreshToken);
    }

    // 로그아웃
    public void logout(HttpServletRequest request, @RequestBody TokenDTO.ServiceToken dto, Principal principal) {
        // accessToken 값
        String accessToken = tokenProvider.resolveToken(request);

        // 만료 기간
        Long expiration = tokenProvider.getExpiration(accessToken);

        // 블랙 리스트 추가
        redisTemplate.opsForValue().set(accessToken, "logout", expiration, TimeUnit.MILLISECONDS);

        // 가지고 있던 refreshToken 제거
        redisTemplate.delete(dto.getRefreshToken());
    }
}