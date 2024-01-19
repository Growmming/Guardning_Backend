package com.growmming.gurdening.token;

import com.growmming.gurdening.domain.Member;
import com.growmming.gurdening.domain.dto.TokenDTO;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import java.security.Key;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

/*
* refresh token을 어디에 저장하고 발급받는 방법은 아직 고민 중
* 추후 추가 예정
* 일단 refresh token을 만들어지는 과정까지는 함.
* refresh token을 이용해서 access token을 발급하는 과정도 아직 없음.
* */
@Slf4j
@Component
public class TokenProvider {
    private final Key key; // JWT를 암호화하기 위한 비밀 키를 저장
    private final long accessTokenValidityTime; // 생성된 액세스 토큰의 유효 시간 저장
    private final long refreshTokenValidityTime;

    public TokenProvider(@Value("${jwt.secret}") String secretKey,
                         @Value("${jwt.expiration.accessToken}") long accessTokenValidityTime,
                         @Value("${jwt.expiration.refreshToken}") long refreshTokenValidityTime) {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        this.key = Keys.hmacShaKeyFor(keyBytes);
        this.accessTokenValidityTime = accessTokenValidityTime;
        this.refreshTokenValidityTime = refreshTokenValidityTime;
    }

    // 로그인 후 생성하는 토큰
    public TokenDTO.ServiceToken createToken(Member member) {
        long nowTime = (new Date()).getTime();

        Date tokenExpiredTime = new Date(nowTime + accessTokenValidityTime);

        // AccessToken 생성
        String accessToken = Jwts.builder()
                .setSubject(member.getId().toString())
                .claim("auth", member.getRole().name())
                .setExpiration(tokenExpiredTime)
                .signWith(key, SignatureAlgorithm.HS256) // 서명
                .compact();

        tokenExpiredTime = new Date(nowTime + refreshTokenValidityTime);

        // RefreshToken 생성
        String refreshToken = Jwts.builder()
                .setExpiration(tokenExpiredTime)
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();

        return TokenDTO.ServiceToken.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build(); // TokenDTO 객체로 반환
    }

    // 복호화를 통해 토큰에 담겨있는 정보를 가져옴
    public Authentication getAuthentication(String accessToken) {

        Claims claims = parseClaims(accessToken); // accessToken에서 클레임 가져옴

        if (claims.get("auth") == null) {
            throw new RuntimeException("권한 정보가 없는 토큰입니다.");
        } // 이 과정을 통과하면 권한 정보가 있는 토큰

        Collection<? extends GrantedAuthority> authorities = Arrays.stream(claims.get("auth").toString().split(","))
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());

        return new UsernamePasswordAuthenticationToken(claims.getSubject(), "", authorities);
    }

    // 헤더에서 토큰값 가져옴
    public String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization"); // "Authorization" : "Bearer 토큰"

        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }

        return null;
    }

    // 토큰의 유효성 검증
    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token);

            return true;
        } catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e) {
            log.info("Invalid JWT Token", e);
        } catch (ExpiredJwtException e) {
            log.info("Expired JWT Token", e); // 만료된 JWT 토큰
        } catch (UnsupportedJwtException e) {
            log.info("Unsupported JWT Token", e); // 지원되지 않는 토큰
        } catch (IllegalArgumentException e) {
            log.info("JWT claims string is empty.", e);
        }
        return false;
    }

    private Claims parseClaims(String accessToken) {
        try {
            return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(accessToken).getBody();
        } catch (ExpiredJwtException e) {
            return e.getClaims();
        }
    }
}

