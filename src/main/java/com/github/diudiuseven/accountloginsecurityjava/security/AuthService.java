package com.github.diudiuseven.accountloginsecurityjava.security;

import java.util.Set;

import jakarta.annotation.PostConstruct;
import org.springframework.stereotype.Service;

/**
 * 登录与会话安全编排入口。
 * 登录失败的所有路径（账号不存在/口令错误/已锁定/已封禁）执行相同的
 * 摘要运算并返回相同的错误内容，不泄露账号是否存在；
 * 内部审计记录真实原因以便追溯，但绝不记录口令。
 */
@Service
public class AuthService {

    public static final String ROLE_ADMIN = "ADMIN";
    private static final String GENERIC_FAILURE = "invalid credentials";

    private final CredentialStore credentials;
    private final LockoutManager lockout;
    private final SessionManager sessions;
    private final AuditLog audit;
    private final StateStore stateStore;

    public AuthService(CredentialStore credentials, LockoutManager lockout,
                       SessionManager sessions, AuditLog audit, StateStore stateStore) {
        this.credentials = credentials;
        this.lockout = lockout;
        this.sessions = sessions;
        this.audit = audit;
        this.stateStore = stateStore;
    }

    /** 启动时恢复持久化状态：已注销会话不复活，锁定不超过既定到期时间。 */
    @PostConstruct
    void restore() {
        PersistedState state = stateStore.load();
        if (state == null) {
            return;
        }
        if (state.accounts() != null) {
            credentials.restore(state.accounts());
        }
        if (state.sessions() != null) {
            sessions.restore(state.sessions());
        }
        if (state.lockout() != null) {
            lockout.restore(state.lockout());
        }
        audit.record("state-restored", "system", "state-store", "ok",
                "savedAt=" + state.savedAt());
    }

    /** 注册/设置凭据（管理端能力，进程内使用）。 */
    public void register(String accountId, char[] password, Set<String> roles) {
        credentials.setCredential(accountId, password, roles);
        audit.record("register", "system", accountId, "ok", "roles=" + roles);
        persist();
    }

    /**
     * 登录：成功返回会话；失败统一抛 INVALID_CREDENTIALS。
     * 无论账号是否存在、是否锁定、是否封禁，都执行相同的口令摘要运算，
     * 错误内容与耗时保持一致。
     */
    public SessionRecord login(String accountId, char[] password, String deviceId, String source) {
        // 1. 常数耗时口令校验（账号不存在时走哑摘要）
        boolean passwordOk = credentials.verify(accountId, password);
        // 2. 锁定与封禁检查（廉价读，不影响主耗时）
        boolean locked = lockout.isLocked(accountId, source);
        CredentialStore.AccountRecord record = credentials.find(accountId);
        boolean banned = record != null && record.banned();

        if (passwordOk && !locked && !banned) {
            lockout.recordSuccess(accountId, source);
            SessionRecord session = sessions.issue(accountId, deviceId,
                    credentials.credentialVersion(accountId));
            audit.record("login", accountId, accountId, "ok", "device=" + deviceId);
            persist();
            return session;
        }

        // 失败：记录节流计数（已锁定期间不延长锁定时长），审计真实原因
        lockout.recordFailure(accountId, source);
        String internalReason = !passwordOk ? "bad-password-or-unknown-account"
                : locked ? "locked" : "banned";
        audit.record("login", accountId, accountId, "denied", internalReason);
        throw new AuthException(AuthFailureReason.INVALID_CREDENTIALS, GENERIC_FAILURE);
    }

    public void logout(String token) {
        sessions.revoke(token);
        audit.record("logout", safeAccount(token), "session", "ok", "revoked");
        persist();
    }

    public SessionRecord renew(String token) {
        SessionRecord renewed = sessions.renew(token);
        checkCredentialVersion(renewed);
        persist();
        return renewed;
    }

    /** 校验会话并返回账号ID；会话被拒绝时原因可区分。 */
    public String requireAccount(String token) {
        SessionRecord record = sessions.requireActive(token);
        checkCredentialVersion(record);
        return record.accountId();
    }

    /** 本人修改口令：需校验旧口令；完成后该账号全部会话失效。 */
    public void changePassword(String token, char[] oldPassword, char[] newPassword) {
        String accountId = requireAccount(token);
        if (!credentials.verify(accountId, oldPassword)) {
            audit.record("change-password", accountId, accountId, "denied", "bad-old-password");
            throw new AuthException(AuthFailureReason.INVALID_CREDENTIALS, GENERIC_FAILURE);
        }
        credentials.setCredential(accountId, newPassword, null);
        sessions.invalidateAllForAccount(accountId);
        audit.record("change-password", accountId, accountId, "ok", "sessions-invalidated");
        persist();
    }

    /** 管理员重置口令；完成后目标账号会话全部失效。 */
    public void resetPassword(String actorToken, String targetAccount, char[] newPassword) {
        String actor = requireAdmin(actorToken, "reset-password", targetAccount);
        if (credentials.find(targetAccount) == null) {
            audit.record("reset-password", actor, targetAccount, "denied", "target-missing");
            throw new AuthException(AuthFailureReason.INVALID_CREDENTIALS, GENERIC_FAILURE);
        }
        credentials.setCredential(targetAccount, newPassword, null);
        sessions.invalidateAllForAccount(targetAccount);
        audit.record("reset-password", actor, targetAccount, "ok", "sessions-invalidated");
        persist();
    }

    /** 管理员封禁；封禁期间登录全部拒绝，既有会话立即失效。 */
    public void ban(String actorToken, String targetAccount) {
        String actor = requireAdmin(actorToken, "ban", targetAccount);
        if (credentials.find(targetAccount) == null) {
            audit.record("ban", actor, targetAccount, "denied", "target-missing");
            throw new AuthException(AuthFailureReason.INVALID_CREDENTIALS, GENERIC_FAILURE);
        }
        credentials.setBanned(targetAccount, true);
        sessions.invalidateAllForAccount(targetAccount);
        audit.record("ban", actor, targetAccount, "ok", "sessions-invalidated");
        persist();
    }

    /** 管理员解封；不恢复封禁前签发的会话（封禁时已失效并留墓碑）。 */
    public void unban(String actorToken, String targetAccount) {
        String actor = requireAdmin(actorToken, "unban", targetAccount);
        if (credentials.find(targetAccount) == null) {
            audit.record("unban", actor, targetAccount, "denied", "target-missing");
            throw new AuthException(AuthFailureReason.INVALID_CREDENTIALS, GENERIC_FAILURE);
        }
        credentials.setBanned(targetAccount, false);
        audit.record("unban", actor, targetAccount, "ok", "");
        persist();
    }

    /** 校验调用方是否为管理员；非管理员抛 FORBIDDEN 并留审计痕迹。 */
    public String requireAdminAccount(String token, String action) {
        return requireAdmin(token, action, "-");
    }

    private String requireAdmin(String token, String action, String target) {
        String actor = requireAccount(token);
        CredentialStore.AccountRecord record = credentials.find(actor);
        if (record == null || !record.roles().contains(ROLE_ADMIN)) {
            audit.record(action, actor, target, "denied", "forbidden");
            throw new AuthException(AuthFailureReason.FORBIDDEN, "forbidden");
        }
        return actor;
    }

    /** 凭据版本不一致（改密/重置后签发的旧会话）视为已失效。 */
    private void checkCredentialVersion(SessionRecord record) {
        CredentialStore.AccountRecord account = credentials.find(record.accountId());
        if (account == null || account.credentialVersion() != record.credentialVersion()) {
            throw new AuthException(AuthFailureReason.SESSION_INVALIDATED, "session invalidated");
        }
        if (account.banned()) {
            throw new AuthException(AuthFailureReason.SESSION_INVALIDATED, "session invalidated");
        }
    }

    private String safeAccount(String token) {
        try {
            SessionRecord record = sessions.snapshot().get(token);
            return record != null ? record.accountId() : "unknown";
        } catch (RuntimeException e) {
            return "unknown";
        }
    }

    private void persist() {
        stateStore.requestPersist(this::snapshot);
    }

    /** 组装全量快照（只含摘要与元数据）。 */
    public PersistedState snapshot() {
        return new PersistedState(credentials.snapshot(), sessions.snapshot(),
                lockout.snapshot(), System.currentTimeMillis());
    }
}
