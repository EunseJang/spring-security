package spring.security.global.exception;

import lombok.extern.slf4j.Slf4j;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.ConstraintViolationException;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import spring.security.global.exception.code.ErrorCode;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

    /** 사용자 정의 예외 처리 */
    @ExceptionHandler(CustomException.class)
    protected ErrorResponseDTO customExcpetion(CustomException e) {
        return new ErrorResponseDTO(e.getErrorCode());
    }

    /** Validation 유효성 검증 오류 처리 */
    @ExceptionHandler(ConstraintViolationException.class)
    protected ResponseEntity<?> constraintViolationException(ConstraintViolationException e) {
        log.error("Validation error");

        List<String> errors = new ArrayList<>();

        // ConstraintViolation을 순회하며 필드와 메시지를 추춣하여 리스트에 추가
        Iterator<ConstraintViolation<?>> iterator = e.getConstraintViolations().iterator();
        while(iterator.hasNext()) {
            ConstraintViolation<?> constraintViolation = iterator.next();
            String field = constraintViolation.getPropertyPath().toString();
            String message = constraintViolation.getMessage();
            errors.add(field + ": " + message);
        }

        return ResponseEntity.badRequest().body(errors);
    }

    /** @Valid 어노테이션을 사용하여 발생한 유효성 검증 오류 처리 */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    protected ResponseEntity<?> methodArgumentNotValidException(MethodArgumentNotValidException e) {
        log.error("Validation error");

        List<String> errors = new ArrayList<>();

        // BindingResult를 통해 유효성 검증 실패한 필드 정보를 추출하여 리스트에 추가
        BindingResult bindingResult = e.getBindingResult();
        for(FieldError fieldError : bindingResult.getFieldErrors()) {
            String field = fieldError.getField();
            String message = fieldError.getDefaultMessage();
            errors.add(field + ": " + message);
        }

        return ResponseEntity.badRequest().body(errors);
    }

    /** 그 외 모든 에러 처리 */
    @ExceptionHandler(Exception.class)
    protected ErrorResponseDTO handleException(Exception e) {
        log.info("Exception.class handler");

        // 내부 서버 오류 응답 반환
        return new ErrorResponseDTO(ErrorCode.INTERNAL_SERVER_ERROR, e.getMessage());
    }
}
