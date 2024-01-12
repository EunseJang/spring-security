package spring.security.global.exception.code;

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
@AllArgsConstructor
public enum ErrorCode {

    // Basic
    INTERNAL_SERVER_ERROR(HttpStatus.INTERNAL_SERVER_ERROR.value(), "내부 서버 오류가 발생했습니다."),

    // Security
    ACCESS_DENIED(HttpStatus.FORBIDDEN.value(), "접근 권한이 없습니다."),
    TOKEN_TIME_OUT(HttpStatus.FORBIDDEN.value(), "토큰이 만료되었습니다."),
    LOGIN_REQUIRED(HttpStatus.UNAUTHORIZED.value(), "로그인이 되지 않았습니다."),
    LOGIN_FAILED_USER_NOT_FOUND(HttpStatus.NOT_FOUND.value(), "계정이 존재하지 않습니다."),
    LOGIN_FAILED_PASSWORD_INCORRECT(HttpStatus.UNAUTHORIZED.value(), "비밀번호가 틀립니다."),
    JWT_TOKEN_ALREADY_LOGGED_OUT(HttpStatus.UNAUTHORIZED.value(), "로그아웃된 인증 정보입니다."),
    JWT_REFRESH_TOKEN_NOT_FOUND(HttpStatus.BAD_REQUEST.value(), "존재하지 않는 RefreshToken 입니다. 다시 로그인 해주세요."),
    JWT_TOKEN_WRONG_TYPE(HttpStatus.FORBIDDEN.value(), "JWT 토큰 형식에 문제가 있습니다."),
    JWT_TOKEN_MALFORMED(HttpStatus.FORBIDDEN.value(), "JWT 토큰 형식에 문제가 있습니다."),

    // User
    USER_NOT_FOUND(HttpStatus.NOT_FOUND.value(), "존재하지 않는 이용자 입니다."),
    USER_ALREADY_EXIST(HttpStatus.BAD_REQUEST.value(), "이미 존재하는 이용자 입니다."),
    PASSWORD_CHECK_INCORRECT(HttpStatus.BAD_REQUEST.value(), "비밀번호 확인이 일치하지 않습니다."),
    EMAIL_AUTH_REQUIRED(HttpStatus.UNAUTHORIZED.value(), "이메일 인증이 완료되지 않았습니다."),
    EMAIL_AUTH_KEY_ERROR(HttpStatus.NOT_FOUND.value(), "이메일 인증 키에 문제가 있습니다.");

    private final int statusCode;
    private final String errorMessage;
}
