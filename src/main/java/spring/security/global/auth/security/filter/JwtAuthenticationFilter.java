package spring.security.global.auth.security.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import spring.security.global.auth.security.jwt.JwtTokenProvider;

import javax.sql.rowset.serial.SerialException;
import java.io.IOException;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    public static final String TOKEN_HEADER = "Authorization";

    private final JwtTokenProvider jwtTokenProvider;

    /** Authorization Header의 token으로 권한 확인 후 SecurityContext에 권한 설정 */
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
        throws ServletException, IOException {

        // Authorization Header에서 토큰 추출
        String token = jwtTokenProvider.resolveTokenFromRequest(request.getHeader(TOKEN_HEADER));

        if(StringUtils.hasText(token) && jwtTokenProvider.validateToken(token)
                && !jwtTokenProvider.isAccessTokenDenied(token)) {

            // 토큰 유효성 검증 성공 시,
            Authentication auth = jwtTokenProvider.getAuthentication(token);

            // SecurityContext에 인증 정보 설정
            SecurityContextHolder.getContext().setAuthentication(auth);
        } else {
            log.info("토큰 유효성 검증 실패 또는 거부된 토큰입니다.");
        }

        // 다음 필터 체인으로 진행
        filterChain.doFilter(request, response);
    }
}
