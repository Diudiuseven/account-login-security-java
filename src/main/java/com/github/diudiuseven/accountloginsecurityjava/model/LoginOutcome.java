package com.github.diudiuseven.accountloginsecurityjava.model;

/** 登录结果。 */
public enum LoginOutcome {
    /** 登录成功。 */
    SUCCESS,
    /** 账号不存在或口令错误（对外不区分）。 */
    BAD_CREDENTIALS,
    /** 账号或来源 IP 被临时锁定。 */
    ACCOUNT_LOCKED,
    /** 账号已被封禁。 */
    ACCOUNT_BANNED
}
