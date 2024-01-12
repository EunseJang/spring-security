package spring.security.global.auth.security.jwt;

import io.jsonwebtoken.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import spring.security.global.auth.dto.TokenResponseDTO;
import spring.security.global.auth.service.AuthService;
import spring.security.global.exception.CustomException;
import spring.security.global.exception.code.ErrorCode;
import spring.security.global.redis.TokenRepository;
import spring.security.user.domain.UserType;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtTokenProvider {

    private final AuthService authService;
    private final TokenRepository tokenRepository;

    @Value("${spring.jwt.secret}")
    private String secretKey;

    public static final String TOKEN_PREFIX = "Bearer ";
    private static final String KEY_ROLES = "reles";

    /** TODO accessToken, refresthToken 만료시간 설정 */
    private static final long ACCESS_TOKEN_EXPIRE_TIME = (long) 1000 * 60 * 60 * 24; // 24시간으로 설정
    private static final long REFRESH_TOKEN_EXPIRE_TIME = (long) 1000 * 60 * 60 * 24 * 30; // 한달로 설정


    /** 토큰 발급 */
    public TokenResponseDTO createTokenResponse(String email, UserType userType) {
        List<String> roles = getRolesByUserType(userType);

        Claims claims = Jwts.claims().setSubject(email);
        claims.put(KEY_ROLES, roles);

        String accessToken = generateToken(claims, ACCESS_TOKEN_EXPIRE_TIME);
        String refreshToken = generateToken(claims, REFRESH_TOKEN_EXPIRE_TIME);

        // redis token Map에 유저의 refreshToken 추가
        tokenRepository.addRefreshToken(email, refreshToken);
        return new TokenResponseDTO(accessToken, refreshToken, email);
    }

    /** 사용자 유형에 따라 role 설정 후 반환 */
    private List<String> getRolesByUserType(UserType userType) {
        List<String> roles = new ArrayList<>();
        roles.add("ROLE_USER");

        if (userType == UserType.ADMIN) { // 관리자인 경우
            roles.add("ROLE_ADMIN");
        }
        return roles;
    }

    /** refreshToken 확인 후 accessToken 재발행 */
    public TokenResponseDTO recreateAccessToken(String refreshToken) {
        if(!this.validateToken(refreshToken)) { // 만료된 토큰인지 확인
            throw new CustomException(ErrorCode.TOKEN_TIME_OUT);
        }

        Claims claims = parseClaims(refreshToken);

        String email = claims.getSubject();
        String findToken = tokenRepository.getRefreshToken(email);

        if(!refreshToken.equals(findToken)) {
            throw new CustomException(ErrorCode.JWT_REFRESH_TOKEN_NOT_FOUND);
        }

        String accessToken = generateToken(claims, ACCESS_TOKEN_EXPIRE_TIME);

        // refreshToken은 재발급 X
        TokenResponseDTO tokenResponse = TokenResponseDTO.builder()
                .email(email)
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();

        return tokenResponse;
    }

    /** JWT Token 생성 (Claims, expiredTime 사용) */
    private String generateToken(Claims claims, Long expiredTime) {
        Date now = new Date();
        Date expired = new Date(now.getTime() + expiredTime);

        return Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(now) // 토큰 생성 시간
                .setExpiration(expired) // 토큰 만료 시간
                .signWith(SignatureAlgorithm.HS512, this.secretKey) // 사용할 암호화 알고리즘, 시크릿 키 설정
                .compact();
    }

    /** 토큰 유효성 검사 */
    public boolean validateToken(String token) {
        if (!StringUtils.hasText(token)) {
            return false; // token이 null이거나 텍스트가 아닌 경우
        }

        Claims claims = this.parseClaims(token);

        // 토큰 만료시간이 현재 시간 이전인지 확인 (만료시간이 더 이전이면 false)
        return !claims.getExpiration().before(new Date());
    }

    /** 주어진 JWT 토큰으로 사용자를 확인하고, 해당 사용자의 정보를 사용하여 Spring Security의 Authentication 객체 생성 */
    public Authentication getAuthentication(String token) {
        // 주어진 토큰으로부터 사용자 이름 추출
        String username = this.getUsername(token);

        // 추출한 사용자 이름을 사용하여 해당 유저 정보를 가져옴
        UserDetails userDetails = authService.loadUserByUsername(username);

        // jwt는 패스워드 대신 토큰을 사용하므로 빈 문자열을 파라미터로 설정
        return new UsernamePasswordAuthenticationToken(userDetails, "", userDetails.getAuthorities());
    }

    /** accessToken이 redis denied map에 포함되어 있는지 여부 확인 */
    public boolean isAccessTokenDenied(String accessToken) {
        return tokenRepository.existBlackListAccessToken(accessToken);
    }

    /** HTTP 요청 헤더에서 받은 토큰에서 "Bearer " prefix를 제거한 토큰 값 반환 */
    public String resolveTokenFromRequest(String token) {
        if (StringUtils.hasText(token) && token.startsWith(TOKEN_PREFIX)) {
            return token.substring(TOKEN_PREFIX.length());
        }

        return null;
    }

    /** token으로 username (사용자 email) 찾기 */
    private String getUsername(String token) {
        return this.parseClaims(token).getSubject();
    }

    /** 토큰 유효성 검사  */
    private Claims parseClaims(String token) {
        try {
            // JWT Token을 파싱하고, 클레임 정보 추출
            return Jwts.parser().setSigningKey(this.secretKey).parseClaimsJws(token).getBody();
        } catch (ExpiredJwtException e) { // 토큰이 만료된 경우
            throw new JwtException(ErrorCode.TOKEN_TIME_OUT.getErrorMessage());
        } catch (SignatureException e) { // 토큰 서명이 잘못된 경우
            throw new JwtException(ErrorCode.JWT_TOKEN_WRONG_TYPE.getErrorMessage());
        } catch (MalformedJwtException e) { // 토큰 형식이 잘못된 경우
            throw new JwtException(ErrorCode.JWT_TOKEN_MALFORMED.getErrorMessage());
        }
    }
}