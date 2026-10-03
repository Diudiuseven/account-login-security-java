package com.github.diudiuseven.accountloginsecurityjava.service;

import com.github.diudiuseven.accountloginsecurityjava.config.SecurityProperties;
import com.github.diudiuseven.accountloginsecurityjava.model.Account;
import com.github.diudiuseven.accountloginsecurityjava.model.AccountStatus;
import com.github.diudiuseven.accountloginsecurityjava.model.Session;
import com.github.diudiuseven.accountloginsecurityjava.model.SessionStatus;
import com.github.diudiuseven.accountloginsecurityjava.model.SessionStrategy;
import com.github.diudiuseven.accountloginsecurityjava.store.SecurityStore;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 会话服务：签发、校验、续期、吊销。
 * 被顶替/被注销/被封禁的会话立即失效，拒绝原因可区分。
 */
@Service
public class SessionService {

    public static final String REASON_LOGOUT = "LOGOUT";
    public static final String REASON_KICK_OUT = "KICK_OUT";
    public static final String REASON_CREDENTIAL_CHANGED = "CREDENTIAL_CHANGED";
    public static final String REASON_ADMIN_RESET = "ADMIN_RESET";
    public static final String REASON_BANNED = "BANNED";
    public static final String REASON_INTERRUPTED = "INTERRUPTED_BY_RESTART";

    public record Validation(boolean valid, String reason, Session session) {
        public static Validation ok(Session s) { return new Validation(true, null, s); }
        public static Validation reject(String reason) { return new Validation(false, reason, null); }
    }

    private final SecurityStore store;
    private final SecurityProperties properties;
    private final AuditService auditService;
    private final SecureRandom random = new SecureRandom();
    private final Base64.Encoder b64 = Base64.getUrlEncoder().withoutPadding();

    /** 按账号条纹锁：签发与批量吊销串行，保证 KICK_OUT 语义确定。 */
    private final ConcurrentHashMap<String, Object> userLocks = new ConcurrentHashMap<>();

    public SessionService(SecurityStore store, SecurityProperties properties, AuditService auditService) {
        this.store = store;
        this.properties = properties;
        this.auditService = auditService;
    }

    /** 某账号的条纹锁（供账号服务复用以保证“改密/封禁”与“签发”互斥）。 */
    public Object userLock(String username) {
        return userLocks.computeIfAbsent(username, k -> new Object());
    }

    /** 签发新会话；KICK_OUT 策略下吊销该账号旧会话。 */
    public Session issue(String username, String ip, String device) {
        synchronized (userLock(username)) {
            if (strategy() == SessionStrategy.KICK_OUT) {
                for (Session s : store.listSessionsByUsername(username)) {
                    if (s.getStatus() == SessionStatus.ACTIVE) {
                        revokeInternal(s, REASON_KICK_OUT, ip);
                    }
                }
            }
            Session session = new Session();
            session.setToken(generateToken());
            session.setUsername(username);
            long now = System.currentTimeMillis();
            session.setIssuedAt(now);
            session.setExpiresAt(now + properties.getSessionTtlMs());
            session.setStatus(SessionStatus.ACTIVE);
            session.setIp(ip);
            session.setDevice(device);
            store.putSession(session);
            auditService.log(AuditService.SESSION_ISSUED, username, ip,
                    "device=" + device + ", strategy=" + strategy(), "SUCCESS");
            return session;
        }
    }

    /** 校验会话：存在性、状态、过期、账号封禁。 */
    public Validation validate(String token) {
        if (token == null || token.isBlank()) {
            return Validation.reject("SESSION_REVOKED");
        }
        Session session = store.getSession(token);
        if (session == null) {
            return Validation.reject("SESSION_REVOKED");
        }
        if (session.getStatus() == SessionStatus.REVOKED) {
            return Validation.reject("SESSION_REVOKED:" + session.getRevokeReason());
        }
        if (session.getStatus() == SessionStatus.EXPIRED) {
            return Validation.reject("SESSION_EXPIRED");
        }
        if (session.getExpiresAt() <= System.currentTimeMillis()) {
            session.setStatus(SessionStatus.EXPIRED);
            store.putSession(session);
            return Validation.reject("SESSION_EXPIRED");
        }
        Account account = store.getAccount(session.getUsername());
        if (account == null) {
            return Validation.reject("SESSION_REVOKED:ACCOUNT_MISSING");
        }
        if (account.getStatus() == AccountStatus.BANNED) {
            return Validation.reject("ACCOUNT_BANNED");
        }
        return Validation.ok(session);
    }

    /** 续期（滑动延期）。 */
    public Validation renew(String token) {
        Validation v = validate(token);
        if (!v.valid()) {
            return v;
        }
        Session s = v.session();
        s.setExpiresAt(System.currentTimeMillis() + properties.getSessionTtlMs());
        store.putSession(s);
        auditService.log(AuditService.SESSION_RENEWED, s.getUsername(), s.getIp(),
                "token=" + abbreviate(token), "SUCCESS");
        return Validation.ok(s);
    }

    /** 吊销单个会话（本人或管理员）。 */
    public void revoke(Session session, String reason, String operatorIp) {
        if (session.getStatus() == SessionStatus.ACTIVE) {
            revokeInternal(session, reason, operatorIp);
        }
    }

    /** 吊销某账号全部会话（凭据变更/封禁/重启中断）。 */
    public int revokeAllForUser(String username, String reason, String operatorIp) {
        synchronized (userLock(username)) {
            int count = 0;
            for (Session s : store.listSessionsByUsername(username)) {
                if (s.getStatus() == SessionStatus.ACTIVE) {
                    revokeInternal(s, reason, operatorIp);
                    count++;
                }
            }
            return count;
        }
    }

    public List<Session> listForUser(String username) {
        return store.listSessionsByUsername(username);
    }

    // ---------------- 内部 ----------------

    private void revokeInternal(Session s, String reason, String operatorIp) {
        s.setStatus(SessionStatus.REVOKED);
        s.setRevokeReason(reason);
        store.putSession(s);
        auditService.log(AuditService.SESSION_REVOKED, s.getUsername(), operatorIp,
                "reason=" + reason + ", token=" + abbreviate(s.getToken()), "SUCCESS");
    }

    private String generateToken() {
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        return b64.encodeToString(bytes);
    }

    private SessionStrategy strategy() {
        try {
            return SessionStrategy.valueOf(properties.getSessionStrategy().trim().toUpperCase());
        } catch (Exception e) {
            return SessionStrategy.KICK_OUT;
        }
    }

    private String abbreviate(String token) {
        if (token == null) {
            return "-";
        }
        return token.length() <= 8 ? token : token.substring(0, 8) + "…";
    }
}
