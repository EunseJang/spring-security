package spring.security.user.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import spring.security.user.domain.UserType;

import java.time.LocalDateTime;

@Getter
@Builder
@AllArgsConstructor
public class JoinResponseDTO {

    private String email;
    private String nickname;
    private UserType userType;
    private LocalDateTime createdAt;

    public static JoinResponseDTO fromDTO(UserDTO userDTO) {
        return JoinResponseDTO.builder()
                .email(userDTO.getEmail())
                .nickname(userDTO.getNickname())
                .createdAt(userDTO.getCreatedAt())
                .userType(userDTO.getUserType())
                .build();
    }
}
