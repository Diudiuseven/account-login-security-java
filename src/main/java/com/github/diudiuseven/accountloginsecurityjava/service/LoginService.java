package com.github.diudiuseven.accountloginsecurityjava.service;

import com.github.diudiuseven.accountloginsecurityjava.config.SecurityProperties;
import com.github.diudiuseven.accountloginsecurityjava.model.Account;
import com.github.diudiuseven.accountloginsecurityjava.model.AccountStatus;
import com.github.diudiuseven.accountloginsecurityjava.model.FailureRecord;
import com.github.diudiuseven.accountloginsecurityjava.model.LoginAttempt;
import com.github.diudiuseven.accountloginsecurityjava.model.LoginOutcome;
import com.github.diudiuseven.accountloginsecurityjava.model.Session;
import com.github.diudiuseven.accountloginsecurityjava.store.SecurityStore;
import org.springframework.stereotype.Service;

import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 登录服务：凭据校验 + 失败节流 + 账号/来源 IP 临时锁定。
 * <ul>
 *   <li>账号不存在与口令错误返回完全相同的结果，且都执行一次 PBKDF2，耗时不泄露账号存在性；</li>
 *   <li>并发失败在按 key 的条纹锁内收敛：一旦达到阈值，后续请求一律锁定，不多放行；</li>
 *   <li>锁定到期自动恢复并清空计数（由恢复逻辑与计数时的窗口判断保证）。</li>
 * </ul>
 */
@Service
public class LoginService {

    public record LoginResult(LoginOutcome outcome, String token, String message) {
        public static LoginResult of(LoginOutcome outcome, String token, String message) {
            return new LoginResult(outcome, token, message);
        }
    }

    private static final String MSG_BAD = "用户名或密码错误";
    private static final String MSG_LOCKED = "账号或来源已被临时锁定，请稍后重试";
    private static final String MSG_BANNED = "账号已被封禁";

    private final SecurityStore store;
    private final PasswordService passwordService;
    private final SessionService sessionService;
    private final AuditService auditService;
    private final SecurityProperties properties;

    /** 失败计数条纹锁：按“维度+标识”串行化计数，不同账号/IP 互不阻塞。 */
    private final ConcurrentHashMap<String, Object> keyLocks = new ConcurrentHashMap<>();

    public LoginService(SecurityStore store, PasswordService passwordService,
                        SessionService sessionService, AuditService auditService,
                        SecurityProperties properties) {
        this.store = store;
        this.passwordService = passwordService;
        this.sessionService = sessionService;
        this.auditService = auditService;
        this.properties = properties;
    }

    public LoginResult login(String username, String password, String ip, String device) {
        String acctKey = "acct:" + (username == null ? "" : username);
        String ipKey = "ip:" + (ip == null ? "unknown" : ip);

        LoginAttempt attempt = new LoginAttempt();
        attempt.setAttemptId(UUID.randomUUID().toString());
        attempt.setUsername(username);
        attempt.setIp(ip);
        attempt.setStartedAt(System.currentTimeMillis());
        attempt.setStatus(LoginAttempt.Status.PENDING);
        store.putLoginAttempt(attempt);

        LoginOutcome outcome;
        String token = null;
        String message;
        String reason;

        try {
            Account account = (username == null || username.isBlank()) ? null : store.getAccount(username);

            // 封禁：直接拒绝（仍执行一次哈希以拉平耗时）
            if (account != null && account.getStatus() == AccountStatus.BANNED) {
                passwordService.matches(password, account.getPasswordHash());
                outcome = LoginOutcome.ACCOUNT_BANNED;
                message = MSG_BANNED;
                reason = "ACCOUNT_BANNED";
            } else {
                boolean acctLocked = isLocked(acctKey);
                boolean ipLocked = isLocked(ipKey);

                if (acctLocked || ipLocked) {
                    // 已锁定：仍执行一次哈希，使响应耗时与正常校验一致
                    String hash = account != null ? account.getPasswordHash() : passwordService.dummyHash();
                    passwordService.matches(password, hash);
                    outcome = LoginOutcome.ACCOUNT_LOCKED;
                    message = MSG_LOCKED;
                    reason = acctLocked ? "ACCOUNT_LOCKED" : "IP_LOCKED";
                } else {
                    // 慢哈希在锁外执行：不同账号/IP 可并行，不互相拖垮吞吐
                    String hash = account != null ? account.getPasswordHash() : passwordService.dummyHash();
                    boolean hashOk = passwordService.matches(password, hash);

                    if (account == null || !hashOk) {
                        LockDecision d1 = recordFailure(acctKey, FailureRecord.Kind.ACCOUNT,
                                properties.getMaxFailures(), properties.getFailWindowMs());
                        LockDecision d2 = recordFailure(ipKey, FailureRecord.Kind.IP,
                                properties.getIpMaxFailures(), properties.getIpFailWindowMs());
                        outcome = (d1 == LockDecision.LOCKED || d2 == LockDecision.LOCKED)
                                ? LoginOutcome.ACCOUNT_LOCKED : LoginOutcome.BAD_CREDENTIALS;
                        message = outcome == LoginOutcome.ACCOUNT_LOCKED ? MSG_LOCKED : MSG_BAD;
                        reason = outcome == LoginOutcome.ACCOUNT_LOCKED
                                ? (d1 == LockDecision.LOCKED ? "ACCOUNT_LOCKED" : "IP_LOCKED")
                                : "BAD_CREDENTIALS";
                    } else {
                        // 成功：清空账号失败计数，签发会话
                        clearFailure(acctKey);
                        Session session = sessionService.issue(username, ip, device);
                        token = session.getToken();
                        outcome = LoginOutcome.SUCCESS;
                        message = "ok";
                        reason = "SUCCESS";
                    }
                }
            }
        } catch (RuntimeException e) {
            attempt.setStatus(LoginAttempt.Status.FAILURE);
            attempt.setReason("INTERNAL_ERROR");
            store.putLoginAttempt(attempt);
            throw e;
        }

        attempt.setStatus(outcome == LoginOutcome.SUCCESS
                ? LoginAttempt.Status.SUCCESS : LoginAttempt.Status.FAILURE);
        attempt.setReason(reason);
        attempt.setSessionToken(token);
        store.putLoginAttempt(attempt);

        if (outcome == LoginOutcome.SUCCESS) {
            auditService.log(AuditService.LOGIN_SUCCESS, username, ip,
                    "device=" + device + ", attemptId=" + attempt.getAttemptId(), "SUCCESS");
        } else {
            auditService.log(AuditService.LOGIN_FAILED, username, ip,
                    "reason=" + reason + ", attemptId=" + attempt.getAttemptId(), "FAILURE");
            if (outcome == LoginOutcome.ACCOUNT_LOCKED) {
                auditService.log(AuditService.ACCOUNT_LOCKED, username, ip,
                        "reason=" + reason, "LOCKED");
            }
        }
        return LoginResult.of(outcome, token, message);
    }

    // ---------------- 失败计数（按 key 串行，收敛锁定结果） ----------------

    private enum LockDecision { ALLOWED, LOCKED }

    private boolean isLocked(String key) {
        Object lock = keyLocks.computeIfAbsent(key, k -> new Object());
        synchronized (lock) {
            FailureRecord rec = store.getFailure(key);
            if (rec == null) {
                return false;
            }
            long now = System.currentTimeMillis();
            if (rec.getLockedUntil() > now) {
                return true;
            }
            // 锁已到期：惰性清空，计数归零
            if (rec.getLockedUntil() > 0) {
                rec.setLockedUntil(0);
                rec.setCount(0);
                rec.setWindowStart(0);
                store.putFailure(rec);
            }
            return false;
        }
    }

    private LockDecision recordFailure(String key, FailureRecord.Kind kind, int maxFailures, long windowMs) {
        Object lock = keyLocks.computeIfAbsent(key, k -> new Object());
        synchronized (lock) {
            long now = System.currentTimeMillis();
            FailureRecord rec = store.getFailure(key);
            if (rec == null) {
                rec = new FailureRecord();
                rec.setKey(key);
                rec.setKind(kind);
                rec.setCount(0);
                rec.setWindowStart(now);
                store.putFailure(rec);
            }
            if (rec.getLockedUntil() > now) {
                return LockDecision.LOCKED;
            }
            if (rec.getWindowStart() == 0 || now - rec.getWindowStart() > windowMs) {
                rec.setWindowStart(now);
                rec.setCount(0);
            }
            rec.setCount(rec.getCount() + 1);
            LockDecision decision;
            // 阈值语义：允许 maxFailures 次失败，第 maxFailures+1 次起锁定
            if (rec.getCount() > maxFailures) {
                rec.setCount(maxFailures + 1);
                rec.setLockedUntil(now + properties.getLockDurationMs());
                decision = LockDecision.LOCKED;
            } else {
                decision = LockDecision.ALLOWED;
            }
            store.putFailure(rec);
            return decision;
        }
    }

    private void clearFailure(String key) {
        Object lock = keyLocks.computeIfAbsent(key, k -> new Object());
        synchronized (lock) {
            store.removeFailure(key);
        }
    }
}
