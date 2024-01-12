package spring.security.global.auth.security.exception;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;


@Slf4j
@Component
public class MyAuthenticationEntryPoint implements AuthenticationEntryPoint {

    /** 인증되지 않은 사용자의 요청이 보내졌을때 호출 */
    @Override
    public void commence(HttpServletRequest request,
                         HttpServletResponse response,
                         AuthenticationException authException) throws IOException, ServletException {

        // 사용자가 로그인되지 않은 상태에서 접근 시 로그 메시지 출력
        log.info("[로그인 X] MyAuthenticationEntryPoint -> /exception/unauthorized");

        // 사용자가 로그인되지 않았으므로 권한이 없는 페이지로 리다이렉트
        response.sendRedirect("/exception/unauthorized");
    }
}
