package spring.security.user.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import spring.security.global.exception.CustomException;
import spring.security.global.exception.code.ErrorCode;
import spring.security.global.util.PasswordUtils;
import spring.security.user.dao.UserRepository;
import spring.security.user.domain.User;
import spring.security.user.dto.JoinRequestDTO;
import spring.security.user.dto.UserDTO;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;

    @Override
    public boolean userExistByEmail(String email) {
        return userRepository.existsByEmail(email);
    }

    @Override
    public UserDTO join(JoinRequestDTO request) {
        validateJoin(request);
        User joinUser = userRepository.save(JoinRequestDTO.toEntity(request));

        return UserDTO.fromEntity(joinUser);
    }

    private void validateJoin(JoinRequestDTO requestDTO) {
        if(userRepository.existsByEmail(requestDTO.getEmail())) {
            throw new CustomException(ErrorCode.USER_ALREADY_EXIST);
        }

        if(!PasswordUtils.equalsPlainText(requestDTO.getPassword(), requestDTO.getPasswordCheck())) {
            throw new CustomException(ErrorCode.PASSWORD_CHECK_INCORRECT);
        }
    }

    @Override
    public UserDTO findByEmail(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new CustomException(ErrorCode.USER_NOT_FOUND));

        return UserDTO.fromEntity(user);
    }
}
