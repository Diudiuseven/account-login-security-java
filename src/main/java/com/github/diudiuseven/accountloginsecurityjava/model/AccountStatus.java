package com.github.diudiuseven.accountloginsecurityjava.model;

/** 账号状态。 */
public enum AccountStatus {
    /** 正常可用。 */
    ACTIVE,
    /** 已封禁：拒绝一切登录，已有会话立即失效。 */
    BANNED
}
