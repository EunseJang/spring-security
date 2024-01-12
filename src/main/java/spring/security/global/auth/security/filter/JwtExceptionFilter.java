package spring.security.global.auth.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtExceptionFilter extends OncePerRequestFilter {

    /** JWT 예외 처리 필터 -> 예외 발생 시 커스텀 응답 생성 */
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        try {
            // 다음 필터 체인으로 진행
            filterChain.doFilter(request, response);
        } catch(JwtException e) {
            String message = e.getMessage();

            // JWT 토큰 타입이 잘못된 경우
            if(message.equals(ErrorCode.JWT_TOKEN_WRONG_TYPE.getDescription())) {
                setResponse(response, ErrorCode.JWT_TOKEN_WRONG_TYPE);
            }
            // JWT 토큰이 만료된 경우
            else if (message.equals(ErrorCode.TOKEN_TIME_OUT.getDescription())) {
                setResponse(response, ErrorCode.TOKEN_TIME_OUT);
            }
        }
    }

    /** 커스텀 응답 생성 */
    private void setResponse(HttpServletResponse response, ErrorCode errorCode)
        throws RuntimeException, IOException {

        // JSON 매핑을 위한 ObjectMapper 객체 생성
        ObjectMapper objectMapper = new JsonMapper();
        // ErrorResponse 객체를 JSON 문자열로 변환
        String responseJson = objectMapper.writeValueAsString(new ErrorResponse(errorCode));

        // HTTP 응답 헤더 설정
        response.setContentType(MediaType.APPLICATION_JSON_VALUE + ";charset=UTF-8");
        response.setStatus(errorCode.getStatusCode()); // HTTP 상태 코드 설정
        response.getWriter().print(responseJson); // HTTP 응답 body에 JSON 응답 전송
    }
}