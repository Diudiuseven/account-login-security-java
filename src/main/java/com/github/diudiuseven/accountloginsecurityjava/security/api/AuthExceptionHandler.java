package com.github.diudiuseven.accountloginsecurityjava.security.api;

import java.util.Map;

import com.github.diudiuseven.accountloginsecurityjava.security.AuthException;
import com.github.diudiuseven.accountloginsecurityjava.security.AuthFailureReason;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * 统一异常映射：
 * 登录失败（INVALID_CREDENTIALS）对外只返回固定文案与固定状态码，
 * 不区分账号不存在/口令错误/锁定/封禁；会话类失败原因可区分。
 */
@RestControllerAdvice
public class AuthExceptionHandler {

    @ExceptionHandler(AuthException.class)
    public ResponseEntity<Map<String, String>> handle(AuthException e) {
        if (e.getReason() == AuthFailureReason.INVALID_CREDENTIALS) {
            // 固定文案与状态码，不泄露账号存在性
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "invalid_credentials"));
        }
        if (e.getReason() == AuthFailureReason.FORBIDDEN) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(Map.of("error", "forbidden"));
        }
        // 会话类原因可区分：session_invalid / session_expired / session_revoked /
        // session_superseded / session_invalidated
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("error", e.getReason().name().toLowerCase()));
    }
}
