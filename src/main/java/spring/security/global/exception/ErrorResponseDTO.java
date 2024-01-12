package spring.security.global.exception;

import lombok.Getter;
import spring.security.global.exception.code.ErrorCode;

@Getter
public class ErrorResponseDTO {

    private int statusCode;
    private ErrorCode errorCode;
    private String errorMessage;

    public ErrorResponseDTO(ErrorCode errorCode) {
        this.statusCode = errorCode.getStatusCode();
        this.errorCode = errorCode;
        this.errorMessage = errorCode.getErrorMessage();
    }

    public ErrorResponseDTO(ErrorCode errorCode, String errorMessage) {
        this.statusCode = errorCode.getStatusCode();
        this.errorCode = errorCode;
        this.errorMessage = errorMessage;
    }
}
