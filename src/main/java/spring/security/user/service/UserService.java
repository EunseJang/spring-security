package spring.security.user.service;

import spring.security.user.dto.JoinRequestDTO;
import spring.security.user.dto.UserDTO;

public interface UserService {

    // TODO 소셜 로그인, 이메일 인증

    /** 이메일로 유저 존재 학인 */
    boolean userExistByEmail(String email);

    /** 유저 회원가입 */
    UserDTO join(JoinRequestDTO request);

    /** 이메일로 유저 조회 */
    UserDTO findByEmail(String email);
}
