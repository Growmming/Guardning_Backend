package com.growmming.gurdening.service;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import com.growmming.gurdening.domain.Member;
import com.growmming.gurdening.domain.Role;
import com.growmming.gurdening.domain.dto.MemberDTO;
import com.growmming.gurdening.domain.dto.TokenDTO;
import com.growmming.gurdening.domain.dto.UserInfoDTO;
import com.growmming.gurdening.repository.MemberRepository;
import com.growmming.gurdening.token.TokenProvider;
import jakarta.servlet.http.HttpServletRequest;
import java.net.URI;
import java.security.Principal;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.ObjectUtils;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.client.RestTemplate;

@Service
public class OAuth2Service {
    private final String GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token";
    private final String googleClientId;
    private final String googleClientSecret;
    private final String googleRedirectUri;
    private final MemberRepository memberRepository;
    private final TokenProvider tokenProvider;
    private final RedisTemplate<String, Object> redisTemplate;

    public OAuth2Service(@Value("${google.client-id}") String googleClientId,
                        @Value("${google.client-secret}") String googleClientSecret,
                        @Value("${google.redirect-uri}") String googleRedirectUri,
                        MemberRepository memberRepository,
                        TokenProvider tokenProvider, RedisTemplate<String, Object> redisTemplate) {
        this.googleClientId = googleClientId;
        this.googleClientSecret = googleClientSecret;
        this.googleRedirectUri = googleRedirectUri;
        this.memberRepository = memberRepository;
        this.tokenProvider = tokenProvider;
        this.redisTemplate = redisTemplate;
    }

    public TokenDTO.GoogleToken getGoogleAccessToken(String code) {
        RestTemplate restTemplate = new RestTemplate(); //  HTTP 요청을 보내기 위한 RestTemplate 객체 생성
        Map<String, String> params = Map.of(
                "code", code,
                "scope", "https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/userinfo.email",
                "client_id", googleClientId,
                "client_secret", googleClientSecret,
                "redirect_uri", googleRedirectUri,
                "grant_type", "authorization_code"
        );

        // 헤더와 파라미터 따로 설정할 필요 없는(자동) 코드
        ResponseEntity<String> responseEntity = restTemplate.postForEntity(GOOGLE_TOKEN_URL, params, String.class);

        if (responseEntity.getStatusCode().is2xxSuccessful()) {
            // 응답 본문(JSON)을 파싱하기 위한 JsonElement 객체 생성
            JsonElement element = JsonParser.parseString(Objects.requireNonNull(responseEntity.getBody()))
                    .getAsJsonObject();

            // JsonElement 객체에서 access_token 추출
            String accessToken = element.getAsJsonObject().get("access_token").getAsString();

            // 추출한 토큰 값들로 TokenDTO.GoogleToken 객체 생성 후 반환
            return new TokenDTO.GoogleToken(accessToken);
        }

        throw new RuntimeException("구글 엑세스 토큰을 가져오는데 실패했습니다.");
    }

    public TokenDTO.ServiceToken loginOrSignUp(MemberDTO.RequestLogin dto) {
        UserInfoDTO userInfoDTO = getUserInfoDTO(dto.getAccessToken());

        if (!userInfoDTO.getVerifiedEmail()) {
            throw new RuntimeException("이메일 인증이 되지 않은 유저입니다.");
        }

        Member member = memberRepository.findByEmail(userInfoDTO.getEmail()).orElseGet(() ->
                memberRepository.save(Member.builder()
                        .email(userInfoDTO.getEmail())
                        .name(userInfoDTO.getName())
                        .profileImage(userInfoDTO.getPictureUrl())
                        .role(Role.USER)
                        .build()) // 등록되어 있지 않으면 새롭게 생성하고 정보 가져옴
        );

        TokenDTO.ServiceToken tokenDTO = tokenProvider.createToken(member);

        Long expiration = tokenProvider.getExpiration(tokenDTO.getRefreshToken());

        redisTemplate.opsForValue().set(tokenDTO.getRefreshToken(), "refreshToken", expiration, TimeUnit.MILLISECONDS);
        return tokenDTO;
    }

    public UserInfoDTO getUserInfoDTO(String accessToken) {
        RestTemplate restTemplate = new RestTemplate();
        String url = "https://www.googleapis.com/oauth2/v2/userinfo?access_token=" + accessToken;

        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Bearer " + accessToken);
        headers.setContentType(MediaType.APPLICATION_JSON);

        RequestEntity<Void> requestEntity = new RequestEntity<>(headers, HttpMethod.GET, URI.create(url));
        ResponseEntity<String> responseEntity = restTemplate.exchange(requestEntity, String.class);

        if (responseEntity.getStatusCode().is2xxSuccessful()) {
            String json = responseEntity.getBody();
            Gson gson = new Gson();
            return gson.fromJson(json, UserInfoDTO.class);
        }

        throw new RuntimeException("유저 정보를 가져오는데 실패했습니다.");
    }

    public TokenDTO.ServiceToken refresh(HttpServletRequest request, TokenDTO.ServiceToken dto) {
        String refreshToken = dto.getRefreshToken();

        // refreshToken이 유효하지 않은 경우 예외 발생
        String isValidate = (String)redisTemplate.opsForValue().get(refreshToken);
        if (ObjectUtils.isEmpty(isValidate)) throw new RuntimeException("401 UNAUTHORIZED, 리프레시 토큰이 유효하지 않습니다.");

        // AccessToken 재발급
        return tokenProvider.createAccessTokenByRefreshToken(request, refreshToken);
    }

    public void logout(HttpServletRequest request, @RequestBody TokenDTO.ServiceToken dto, Principal principal) {
        String accessToken = tokenProvider.resolveToken(request);
        Long expiration = tokenProvider.getExpiration(accessToken);
        redisTemplate.opsForValue().set(accessToken, "logout", expiration, TimeUnit.MILLISECONDS);
        redisTemplate.delete(dto.getRefreshToken());
    }

}
