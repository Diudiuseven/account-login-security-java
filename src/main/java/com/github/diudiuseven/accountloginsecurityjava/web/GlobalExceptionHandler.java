package com.github.diudiuseven.accountloginsecurityjava.web;

import com.github.diudiuseven.accountloginsecurityjava.web.dto.ApiError;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/** 全局异常处理：统一错误响应，不泄露堆栈与内部细节。 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(SecurityApiException.class)
    public ResponseEntity<ApiError> handleSecurity(SecurityApiException ex) {
        HttpStatus status = switch (ex.getCode()) {
            case BAD_CREDENTIALS, UNAUTHORIZED, SESSION_EXPIRED, SESSION_REVOKED -> HttpStatus.UNAUTHORIZED;
            case ACCOUNT_LOCKED -> HttpStatus.LOCKED;
            case ACCOUNT_BANNED, FORBIDDEN -> HttpStatus.FORBIDDEN;
            case NOT_FOUND -> HttpStatus.NOT_FOUND;
            case VALIDATION_ERROR -> HttpStatus.BAD_REQUEST;
            case INTERNAL_ERROR -> HttpStatus.INTERNAL_SERVER_ERROR;
        };
        return ResponseEntity.status(status).body(new ApiError(ex.getCode().name(), ex.getMessage()));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiError> handleOther(Exception ex) {
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(new ApiError(ErrorCode.INTERNAL_ERROR.name(), "服务器内部错误"));
    }
}
