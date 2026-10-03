package com.github.diudiuseven.accountloginsecurityjava.security;

/**
 * 认证/会话/授权异常。消息为固定文案，不包含口令、账号存在性等敏感信息。
 */
public class AuthException extends RuntimeException {

    private final AuthFailureReason reason;

    public AuthException(AuthFailureReason reason, String message) {
        super(message);
        this.reason = reason;
    }

    public AuthFailureReason getReason() {
        return reason;
    }
}
