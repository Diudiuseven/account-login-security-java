package com.github.diudiuseven.accountloginsecurityjava.web;

/** 安全相关业务异常。message 不得包含明文口令。 */
public class SecurityApiException extends RuntimeException {

    private final ErrorCode code;

    public SecurityApiException(ErrorCode code, String message) {
        super(message);
        this.code = code;
    }

    public ErrorCode getCode() { return code; }
}
