package com.github.diudiuseven.accountloginsecurityjava.security;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.stereotype.Component;

/**
 * 会话签发、续期、注销与多端顶替。
 * 同账号的签发/顶替在该账号的锁上串行化；单次会话状态变更通过
 * ConcurrentHashMap.compute 原子完成，任何读都看不到写了一半的状态。
 * 被注销/被顶替的会话保留墓碑直到原定到期时间，保证重启后不会复活。
 */
@Component
public class SessionManager {

    private final SecurityProperties properties;
    private final ConcurrentHashMap<String, SessionRecord> sessions = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Object> accountLocks = new ConcurrentHashMap<>();
    private final SecureRandom random = new SecureRandom();

    public SessionManager(SecurityProperties properties) {
        this.properties = properties;
    }

    /** 签发新会话；策略为顶替时，同账号旧活跃会话原子地转为 SUPERSEDED。 */
    public SessionRecord issue(String accountId, String deviceId, long credentialVersion) {
        long now = System.currentTimeMillis();
        SessionRecord created = new SessionRecord(newToken(), accountId, deviceId,
                now, now + properties.getSessionTtl().toMillis(),
                credentialVersion, SessionRecord.Status.ACTIVE);
        synchronized (lockFor(accountId)) {
            if (!properties.isAllowConcurrentSessions()) {
                sessions.replaceAll((token, record) ->
                        record.accountId().equals(accountId)
                                && record.status() == SessionRecord.Status.ACTIVE
                                ? record.withStatus(SessionRecord.Status.SUPERSEDED)
                                : record);
            }
            sessions.put(created.token(), created);
        }
        return created;
    }

    /** 续期；非活跃会话抛出带区分原因的异常。 */
    public SessionRecord renew(String token) {
        requireActive(token);
        long newExpiry = System.currentTimeMillis() + properties.getSessionTtl().toMillis();
        SessionRecord[] updated = new SessionRecord[1];
        sessions.computeIfPresent(token, (t, record) -> {
            if (record.status() == SessionRecord.Status.ACTIVE
                    && record.expiresAt() > System.currentTimeMillis()) {
                updated[0] = record.withExpiry(newExpiry);
                return updated[0];
            }
            return record;
        });
        if (updated[0] == null) {
            // 并发下会话刚被注销/顶替/失效，以最新状态给出区分原因
            return requireActive(token);
        }
        return updated[0];
    }

    /** 注销（主动登出），立即生效。 */
    public void revoke(String token) {
        transition(token, SessionRecord.Status.REVOKED);
    }

    /** 使某账号全部活跃会话失效（敏感操作后调用）。 */
    public void invalidateAllForAccount(String accountId) {
        synchronized (lockFor(accountId)) {
            sessions.replaceAll((token, record) ->
                    record.accountId().equals(accountId)
                            && record.status() == SessionRecord.Status.ACTIVE
                            ? record.withStatus(SessionRecord.Status.INVALIDATED)
                            : record);
        }
    }

    private void transition(String token, SessionRecord.Status target) {
        sessions.computeIfPresent(token, (t, record) ->
                record.status() == SessionRecord.Status.ACTIVE
                        ? record.withStatus(target) : record);
    }

    /** 校验会话，返回活跃记录；否则抛 AuthException 并带区分原因。 */
    public SessionRecord requireActive(String token) {
        if (token == null || token.isBlank()) {
            throw new AuthException(AuthFailureReason.SESSION_INVALID, "session invalid");
        }
        SessionRecord record = sessions.get(token);
        if (record == null) {
            throw new AuthException(AuthFailureReason.SESSION_INVALID, "session invalid");
        }
        switch (record.status()) {
            case REVOKED ->
                    throw new AuthException(AuthFailureReason.SESSION_REVOKED, "session revoked");
            case SUPERSEDED ->
                    throw new AuthException(AuthFailureReason.SESSION_SUPERSEDED, "session superseded");
            case INVALIDATED ->
                    throw new AuthException(AuthFailureReason.SESSION_INVALIDATED, "session invalidated");
            case ACTIVE -> {
                if (record.expiresAt() <= System.currentTimeMillis()) {
                    throw new AuthException(AuthFailureReason.SESSION_EXPIRED, "session expired");
                }
                return record;
            }
            default -> throw new AuthException(AuthFailureReason.SESSION_INVALID, "session invalid");
        }
    }

    /** 快照：保留未到期会话（含注销/顶替墓碑），保证重启后状态可解释且不复活。 */
    public Map<String, SessionRecord> snapshot() {
        long now = System.currentTimeMillis();
        Map<String, SessionRecord> out = new HashMap<>();
        sessions.forEach((token, record) -> {
            if (record.expiresAt() > now) {
                out.put(token, record);
            }
        });
        return out;
    }

    /** 恢复：丢弃已到期会话；未到期会话（含墓碑）原样恢复。 */
    public void restore(Map<String, SessionRecord> saved) {
        if (saved == null) {
            return;
        }
        long now = System.currentTimeMillis();
        sessions.clear();
        saved.forEach((token, record) -> {
            if (record.expiresAt() > now) {
                sessions.put(token, record);
            }
        });
    }

    private Object lockFor(String accountId) {
        return accountLocks.computeIfAbsent(accountId, k -> new Object());
    }

    private String newToken() {
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
