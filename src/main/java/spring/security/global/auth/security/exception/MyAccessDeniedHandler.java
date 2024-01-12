package spring.security.global.auth.security.exception;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Slf4j
@Component
public class MyAccessDeniedHandler implements AccessDeniedHandler {

    @Override
    public void handle(HttpServletRequest request,
                       HttpServletResponse response,
                       AccessDeniedException accessDeniedException) throws IOException, ServletException {

        // 접근 권한이 없는 상황에서 어떤 URL에 접근을 시도했는지 기록
        log.info("[접근 권한 X] URL : [{}]", request.getRequestURL());

        // 접근 권한이 없을 경우, 특정 페이지로 리다이렉트
        response.sendRedirect("/exception/auth-denied");
    }
}
