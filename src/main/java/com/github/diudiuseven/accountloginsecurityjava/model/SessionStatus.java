package com.github.diudiuseven.accountloginsecurityjava.model;

/** 会话状态。 */
public enum SessionStatus {
    /** 有效。 */
    ACTIVE,
    /** 已吊销（注销/被顶替/凭据变更/封禁/重启中断），不可恢复。 */
    REVOKED,
    /** 已过期。 */
    EXPIRED
}
