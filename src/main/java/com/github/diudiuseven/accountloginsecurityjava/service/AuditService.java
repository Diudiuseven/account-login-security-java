package com.github.diudiuseven.accountloginsecurityjava.service;

import com.github.diudiuseven.accountloginsecurityjava.model.AuditEvent;
import com.github.diudiuseven.accountloginsecurityjava.store.SecurityStore;
import org.springframework.stereotype.Service;

/** 安全审计：所有敏感操作追加写审计日志，跨重启可追溯。 */
@Service
public class AuditService {

    public static final String LOGIN_SUCCESS = "LOGIN_SUCCESS";
    public static final String LOGIN_FAILED = "LOGIN_FAILED";
    public static final String ACCOUNT_LOCKED = "ACCOUNT_LOCKED";
    public static final String SESSION_ISSUED = "SESSION_ISSUED";
    public static final String SESSION_REVOKED = "SESSION_REVOKED";
    public static final String SESSION_RENEWED = "SESSION_RENEWED";
    public static final String PASSWORD_CHANGED = "PASSWORD_CHANGED";
    public static final String PASSWORD_RESET = "PASSWORD_RESET";
    public static final String ACCOUNT_BANNED = "ACCOUNT_BANNED";
    public static final String ACCOUNT_UNBANNED = "ACCOUNT_UNBANNED";
    public static final String ACCOUNT_CREATED = "ACCOUNT_CREATED";
    public static final String UNAUTHORIZED_ACCESS = "UNAUTHORIZED_ACCESS";

    private final SecurityStore store;

    public AuditService(SecurityStore store) {
        this.store = store;
    }

    public void log(String eventType, String username, String ip, String detail, String result) {
        AuditEvent e = new AuditEvent();
        e.setTimestamp(System.currentTimeMillis());
        e.setEventType(eventType);
        e.setUsername(username == null ? "-" : username);
        e.setIp(ip == null ? "-" : ip);
        // 审计明细同样不得包含明文口令
        e.setDetail(sanitize(detail));
        e.setResult(result);
        store.appendAudit(e);
    }

    private String sanitize(String detail) {
        return detail == null ? "-" : detail;
    }
}
