package com.github.diudiuseven.accountloginsecurityjava.security;

import java.time.Duration;

/**
 * 测试用组件栈：绕过 Spring 直接构造，使用低迭代次数加速口令摘要。
 * 可通过指定 stateFile 模拟进程重启（新建栈加载同一文件）。
 */
final class TestStack {

    final SecurityProperties properties;
    final PasswordHasher hasher;
    final CredentialStore credentials;
    final LockoutManager lockout;
    final SessionManager sessions;
    final AuditLog audit;
    final StateStore stateStore;
    final AuthService authService;

    TestStack(SecurityProperties properties) {
        this.properties = properties;
        this.hasher = new PasswordHasher(properties);
        this.credentials = new CredentialStore(hasher);
        this.lockout = new LockoutManager(properties);
        this.sessions = new SessionManager(properties);
        this.audit = new AuditLog();
        this.stateStore = new StateStore(properties);
        this.authService = new AuthService(credentials, lockout, sessions, audit, stateStore);
        this.authService.restore();
    }

    static TestStack create() {
        return new TestStack(fastProperties(""));
    }

    static TestStack create(String stateFile) {
        return new TestStack(fastProperties(stateFile));
    }

    static SecurityProperties fastProperties(String stateFile) {
        SecurityProperties p = new SecurityProperties();
        p.setHashIterations(1_000);
        p.setFailureWindow(Duration.ofSeconds(5));
        p.setMaxFailures(3);
        p.setLockDuration(Duration.ofMillis(500));
        p.setSessionTtl(Duration.ofSeconds(30));
        p.setAllowConcurrentSessions(false);
        p.setStateFile(stateFile);
        p.setPersistInterval(Duration.ofMillis(10));
        return p;
    }

    void flush() {
        stateStore.persistNow(authService::snapshot);
    }

    void shutdown() {
        stateStore.shutdown();
    }
}
