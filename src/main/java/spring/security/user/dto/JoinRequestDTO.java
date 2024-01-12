package spring.security.user.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import spring.security.global.util.PasswordUtils;
import spring.security.user.domain.User;
import spring.security.user.domain.UserType;

@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class JoinRequestDTO {

    private String email;
    private String password;
    private String passwordCheck;
    private String nickname;

    public static User toEntity(JoinRequestDTO request) {
        return User.builder()
                .email(request.getEmail())
                .password(PasswordUtils.encPassword(request.getPassword()))
                .nickname(request.getNickname())
                .userType(UserType.BASIC)
                .build();

    }
}
