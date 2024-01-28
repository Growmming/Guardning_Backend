package com.growmming.gurdening.util;

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.http.HttpStatus;

@AllArgsConstructor
@Getter
public enum ErrorCode {

    /* 400 BAD_REQUEST : 잘못된 요청 */
    INVALID_GOOGLE_VALUE(HttpStatus.BAD_REQUEST, "잘못된 요청으로 카카오 서버의 응답을 받지 못했습니다."),

    /* 401 UNAUTHORIZED : 인증되지 않은 사용자 */
    INVALID_AUTH_TOKEN(HttpStatus.UNAUTHORIZED, "인증 토큰이 유효하지 않습니다."),
    INVALID_REFRESH_TOKEN(HttpStatus.UNAUTHORIZED, "리프레시 토큰이 유효하지 않습니다."),

    /* 404 NOT_FOUND : 리소스를 찾을 수 없음 */
    EMAIL_NOT_FOUND(HttpStatus.NOT_FOUND, "사용자의 이메일을 찾을 수 없습니다.");

    private final HttpStatus httpStatus;
    private final String message;
}
