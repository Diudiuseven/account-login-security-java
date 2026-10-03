package com.github.diudiuseven.accountloginsecurityjava.security;

import java.util.Map;

/**
 * 可持久化的全量状态：凭据摘要、会话（含注销/顶替墓碑）、失败锁定。
 * 只含摘要与时间戳，绝不含明文口令。
 */
public record PersistedState(
        Map<String, CredentialStore.AccountRecord> accounts,
        Map<String, SessionRecord> sessions,
        LockoutManager.LockoutSnapshot lockout,
        long savedAt) {
}
