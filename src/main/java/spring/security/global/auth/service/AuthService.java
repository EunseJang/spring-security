package spring.security.global.auth.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import spring.security.global.auth.dto.LoginDTO;
import spring.security.global.auth.security.principal.PrincipalDetails;
import spring.security.global.exception.CustomException;
import spring.security.global.exception.code.ErrorCode;
import spring.security.global.redis.TokenRepository;
import spring.security.global.util.PasswordUtils;
import spring.security.user.dao.UserRepository;
import spring.security.user.domain.User;
import spring.security.user.dto.UserDTO;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService implements UserDetailsService {

    private final UserRepository userRepository;
    private final TokenRepository tokenRepository;

    /** 로그인 인증 */
    public UserDTO authenticateUser(LoginDTO loginDTO) {
        User user = userRepository.findByEmail(loginDTO.getEmail())
                .orElseThrow(() -> new CustomException(ErrorCode.LOGIN_FAILED_USER_NOT_FOUND));

        // 비밀번호 체크
        if(!PasswordUtils.equalsPlainTextAndHashed(loginDTO.getPassword(), user.getPassword())) {
            throw new CustomException(ErrorCode.LOGIN_FAILED_PASSWORD_INCORRECT);
        }

        return UserDTO.fromEntity(user);
    }

    /** 로그아웃 */
    public boolean logout(String accessToken, String email) {
        boolean result = tokenRepository.deleteRefreshToken(email);
        tokenRepository.addBlackListAccessToken(accessToken);

        return result;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByEmail(username)
                .orElseThrow(() -> new UsernameNotFoundException("회원 정보가 존재하지 않습니다."));

        log.info("로그인 성공 [ID : {}]", user.getEmail());
        return new PrincipalDetails(user);
    }
}
