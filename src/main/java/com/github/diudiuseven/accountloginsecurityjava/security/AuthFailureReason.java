package com.github.diudiuseven.accountloginsecurityjava.security;

/**
 * 认证/会话失败原因码。
 *
 * 登录失败对外只暴露 {@link #INVALID_CREDENTIALS}，不存在的账号、错误口令、
 * 已锁定、已封禁在错误内容与耗时上保持一致，避免泄露账号是否存在。
 * 会话类失败原因可区分，因为持有会话即证明账号存在。
 */
public enum AuthFailureReason {
    /** 登录失败（统一口径：账号不存在/口令错误/已锁定/已封禁）。 */
    INVALID_CREDENTIALS,
    /** 会话不存在或无法识别。 */
    SESSION_INVALID,
    /** 会话已过期。 */
    SESSION_EXPIRED,
    /** 会话已被主动注销。 */
    SESSION_REVOKED,
    /** 会话被同账号新登录顶替。 */
    SESSION_SUPERSEDED,
    /** 会话因敏感操作（改密/重置/封禁）被失效。 */
    SESSION_INVALIDATED,
    /** 越权：缺少执行敏感操作所需的角色或身份。 */
    FORBIDDEN
}
