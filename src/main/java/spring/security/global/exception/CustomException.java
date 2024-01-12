package spring.security.global.exception;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import spring.security.global.exception.code.ErrorCode;

@Getter
@NoArgsConstructor
@AllArgsConstructor
public class CustomException extends RuntimeException {

    private ErrorCode errorCode;
    private String errorMessage;

    public CustomException(ErrorCode errorCode) {
        super(errorCode.getErrorMessage());

        this.errorCode = errorCode;
        this.errorMessage = errorCode.getErrorMessage();
    }
}