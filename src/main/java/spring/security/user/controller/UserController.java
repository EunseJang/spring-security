package spring.security.user.controller;

import io.swagger.v3.oas.annotations.Operation;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import spring.security.user.dto.JoinRequestDTO;
import spring.security.user.dto.JoinResponseDTO;
import spring.security.user.dto.UserDTO;
import spring.security.user.service.UserService;

@Slf4j
@RestController
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @Operation(summary = "회원가입")
    @PostMapping("/api/v1/auth/join")
    public ResponseEntity<?> join(@RequestBody JoinRequestDTO request) {
        UserDTO joinUser = userService.join(request);

        return ResponseEntity.ok(JoinResponseDTO.fromDTO(joinUser));
    }
}
