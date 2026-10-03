package com.github.diudiuseven.accountloginsecurityjava.web;

/** 可区分的错误码。 */
public enum ErrorCode {
    /** 账号不存在或口令错误（对外不区分）。 */
    BAD_CREDENTIALS,
    /** 账号或来源被临时锁定。 */
    ACCOUNT_LOCKED,
    /** 账号已被封禁。 */
    ACCOUNT_BANNED,
    /** 会话已过期。 */
    SESSION_EXPIRED,
    /** 会话已被吊销（注销/顶替/封禁）。 */
    SESSION_REVOKED,
    /** 未认证（缺少会话）。 */
    UNAUTHORIZED,
    /** 已认证但权限不足。 */
    FORBIDDEN,
    /** 请求的资源不存在。 */
    NOT_FOUND,
    /** 参数校验失败。 */
    VALIDATION_ERROR,
    /** 内部错误（不泄露细节）。 */
    INTERNAL_ERROR
}
