package spring.security.global.auth.controller;

import io.swagger.v3.oas.annotations.Operation;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;
import spring.security.global.auth.dto.LoginDTO;
import spring.security.global.auth.dto.TokenResponseDTO;
import spring.security.global.auth.security.jwt.JwtTokenProvider;
import spring.security.global.auth.security.principal.PrincipalDetails;
import spring.security.global.auth.service.AuthService;
import spring.security.user.dto.UserDTO;

@Slf4j
@RestController
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final JwtTokenProvider jwtTokenProvider;

    @Operation(summary = "로그인, JWT 토큰 발생", description = "Authorization 헤더에 JWT 토큰을 포함하여 인증 처리")
    @PostMapping("/login/user")
    public ResponseEntity<?> login(@RequestBody LoginDTO loginDTO) {
        UserDTO user = authService.authenticateUser(loginDTO);
        TokenResponseDTO tokenResponseDTO = jwtTokenProvider.createTokenResponse(user.getEmail(), user.getUserType());

        return ResponseEntity.ok(tokenResponseDTO);
    }

    @Operation(summary = "RefreshToken을 통해 AccessToken 재발급")
    @PostMapping("/login/reissue")
    public ResponseEntity<?> reissueToken(@RequestHeader("RefreshToken") String refreshToken) {
        TokenResponseDTO tokenResponseDTO = jwtTokenProvider.recreateAccessToken(refreshToken);

        return ResponseEntity.ok(tokenResponseDTO);
    }

    @Operation(summary = "Logout : refreshToken 삭제")
    @PostMapping("/logout/user")
    public ResponseEntity<?> logout(@AuthenticationPrincipal PrincipalDetails principalDetails,
                                    @RequestHeader("Authorization") String accessToken) {
        log.info("Access Token : {}", accessToken);

        String token = jwtTokenProvider.resolveTokenFromRequest(accessToken);
        authService.logout(token, principalDetails.getEmail());

        return ResponseEntity.ok("logout success");
    }
}
