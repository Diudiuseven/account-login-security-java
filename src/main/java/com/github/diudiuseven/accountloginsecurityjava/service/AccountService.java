package com.github.diudiuseven.accountloginsecurityjava.service;

import com.github.diudiuseven.accountloginsecurityjava.config.SecurityProperties;
import com.github.diudiuseven.accountloginsecurityjava.model.Account;
import com.github.diudiuseven.accountloginsecurityjava.model.AccountStatus;
import com.github.diudiuseven.accountloginsecurityjava.model.Role;
import com.github.diudiuseven.accountloginsecurityjava.store.SecurityStore;
import com.github.diudiuseven.accountloginsecurityjava.web.ErrorCode;
import com.github.diudiuseven.accountloginsecurityjava.web.SecurityApiException;
import org.springframework.stereotype.Service;

/** 账号服务：开户、改密、重置、封禁/解封。敏感操作后相关会话按策略失效。 */
@Service
public class AccountService {

    private final SecurityStore store;
    private final PasswordService passwordService;
    private final SessionService sessionService;
    private final AuditService auditService;
    private final SecurityProperties properties;

    public AccountService(SecurityStore store, PasswordService passwordService,
                          SessionService sessionService, AuditService auditService,
                          SecurityProperties properties) {
        this.store = store;
        this.passwordService = passwordService;
        this.sessionService = sessionService;
        this.auditService = auditService;
        this.properties = properties;
    }

    public Account createAccount(String username, String rawPassword, String roleName) {
        if (username == null || username.isBlank()) {
            throw new SecurityApiException(ErrorCode.VALIDATION_ERROR, "用户名不能为空");
        }
        if (rawPassword == null || rawPassword.isEmpty()) {
            throw new SecurityApiException(ErrorCode.VALIDATION_ERROR, "口令不能为空");
        }
        if (store.getAccount(username) != null) {
            throw new SecurityApiException(ErrorCode.VALIDATION_ERROR, "账号已存在");
        }
        Role role = parseRole(roleName);
        Account account = new Account();
        account.setUsername(username);
        account.setPasswordHash(passwordService.hash(rawPassword));
        account.setRole(role);
        account.setStatus(AccountStatus.ACTIVE);
        long now = System.currentTimeMillis();
        account.setCreatedAt(now);
        account.setUpdatedAt(now);
        store.putAccount(account);
        auditService.log(AuditService.ACCOUNT_CREATED, username, "-",
                "role=" + role, "SUCCESS");
        return account;
    }

    /** 本人改密：校验原口令；成功后按策略吊销全部会话。 */
    public void changePassword(String username, String oldPassword, String newPassword) {
        Account account = getRequired(username);
        if (!passwordService.matches(oldPassword, account.getPasswordHash())) {
            throw new SecurityApiException(ErrorCode.BAD_CREDENTIALS, "原口令错误");
        }
        if (newPassword == null || newPassword.isEmpty()) {
            throw new SecurityApiException(ErrorCode.VALIDATION_ERROR, "新口令不能为空");
        }
        synchronized (sessionService.userLock(username)) {
            account.setPasswordHash(passwordService.hash(newPassword));
            account.setUpdatedAt(System.currentTimeMillis());
            store.putAccount(account);
            if (properties.isRevokeOnCredentialChange()) {
                sessionService.revokeAllForUser(username, SessionService.REASON_CREDENTIAL_CHANGED, null);
            }
        }
        auditService.log(AuditService.PASSWORD_CHANGED, username, "-",
                "revokeSessions=" + properties.isRevokeOnCredentialChange(), "SUCCESS");
    }

    /** 管理员重置口令：重置后吊销该账号全部会话。 */
    public void resetPassword(String username, String newPassword, String operator) {
        Account account = getRequired(username);
        if (newPassword == null || newPassword.isEmpty()) {
            throw new SecurityApiException(ErrorCode.VALIDATION_ERROR, "新口令不能为空");
        }
        synchronized (sessionService.userLock(username)) {
            account.setPasswordHash(passwordService.hash(newPassword));
            account.setUpdatedAt(System.currentTimeMillis());
            store.putAccount(account);
            sessionService.revokeAllForUser(username, SessionService.REASON_ADMIN_RESET, operator);
        }
        auditService.log(AuditService.PASSWORD_RESET, operator, "-",
                "target=" + username, "SUCCESS");
    }

    /** 封禁：账号置为 BANNED，吊销全部会话；封禁期间登录一律拒绝。 */
    public void ban(String username, String operator) {
        Account account = getRequired(username);
        synchronized (sessionService.userLock(username)) {
            account.setStatus(AccountStatus.BANNED);
            account.setUpdatedAt(System.currentTimeMillis());
            store.putAccount(account);
            sessionService.revokeAllForUser(username, SessionService.REASON_BANNED, operator);
        }
        auditService.log(AuditService.ACCOUNT_BANNED, operator, "-",
                "target=" + username, "SUCCESS");
    }

    /** 解封：账号恢复 ACTIVE；封禁前签发的会话已被吊销，不得沿用。 */
    public void unban(String username, String operator) {
        Account account = getRequired(username);
        synchronized (sessionService.userLock(username)) {
            account.setStatus(AccountStatus.ACTIVE);
            account.setUpdatedAt(System.currentTimeMillis());
            store.putAccount(account);
            // 注意：不恢复任何会话——它们在封禁时已被吊销（REVOKED 不可恢复）
        }
        auditService.log(AuditService.ACCOUNT_UNBANNED, operator, "-",
                "target=" + username, "SUCCESS");
    }

    public Account getRequired(String username) {
        Account account = store.getAccount(username);
        if (account == null) {
            throw new SecurityApiException(ErrorCode.NOT_FOUND, "账号不存在");
        }
        return account;
    }

    private Role parseRole(String roleName) {
        if (roleName == null || roleName.isBlank()) {
            return Role.USER;
        }
        try {
            return Role.valueOf(roleName.trim().toUpperCase());
        } catch (Exception e) {
            throw new SecurityApiException(ErrorCode.VALIDATION_ERROR, "非法角色: " + roleName);
        }
    }
}
