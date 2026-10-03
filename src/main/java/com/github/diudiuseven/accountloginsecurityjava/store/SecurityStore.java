package com.github.diudiuseven.accountloginsecurityjava.store;

import com.github.diudiuseven.accountloginsecurityjava.model.Account;
import com.github.diudiuseven.accountloginsecurityjava.model.AuditEvent;
import com.github.diudiuseven.accountloginsecurityjava.model.FailureRecord;
import com.github.diudiuseven.accountloginsecurityjava.model.LoginAttempt;
import com.github.diudiuseven.accountloginsecurityjava.model.Session;

import java.util.Collection;
import java.util.List;

/**
 * 安全状态存储。所有方法必须保证：
 * 1. 调用方永远读不到写了一半的中间状态；
 * 2. 状态变更在返回前已持久化（崩溃不丢已确认的结果）。
 */
public interface SecurityStore {

    /** 启动时加载数据并执行崩溃恢复。 */
    void init();

    Account getAccount(String username);
    void putAccount(Account account);
    Collection<Account> listAccounts();

    Session getSession(String token);
    void putSession(Session session);
    Collection<Session> listSessions();
    List<Session> listSessionsByUsername(String username);

    FailureRecord getFailure(String key);
    void putFailure(FailureRecord record);
    void removeFailure(String key);
    Collection<FailureRecord> listFailures();

    void putLoginAttempt(LoginAttempt attempt);
    LoginAttempt getLoginAttempt(String attemptId);
    Collection<LoginAttempt> listLoginAttempts();

    void appendAudit(AuditEvent event);
}
