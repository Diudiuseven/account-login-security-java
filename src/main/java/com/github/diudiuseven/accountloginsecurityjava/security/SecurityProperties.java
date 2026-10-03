package com.github.diudiuseven.accountloginsecurityjava.security;

import java.time.Duration;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * 登录与会话安全的可配置项。所有项都有安全的默认值，可通过
 * application.properties 中以 security.auth 为前缀的配置覆盖。
 */
@ConfigurationProperties(prefix = "security.auth")
public class SecurityProperties {

    /** 口令摘要算法迭代次数。 */
    private int hashIterations = 120_000;

    /** 连续失败统计窗口。 */
    private Duration failureWindow = Duration.ofMinutes(10);

    /** 窗口内允许的最大失败次数，达到即锁定。 */
    private int maxFailures = 5;

    /** 锁定时长。 */
    private Duration lockDuration = Duration.ofMinutes(15);

    /** 会话有效期。 */
    private Duration sessionTtl = Duration.ofHours(2);

    /** 多端登录策略：true 表示并存，false 表示新登录顶替旧会话。 */
    private boolean allowConcurrentSessions = false;

    /** 状态持久化文件路径，空字符串表示仅内存。 */
    private String stateFile = "";

    /** 持久化落盘间隔（防抖）。 */
    private Duration persistInterval = Duration.ofMillis(200);

    public int getHashIterations() {
        return hashIterations;
    }

    public void setHashIterations(int hashIterations) {
        this.hashIterations = hashIterations;
    }

    public Duration getFailureWindow() {
        return failureWindow;
    }

    public void setFailureWindow(Duration failureWindow) {
        this.failureWindow = failureWindow;
    }

    public int getMaxFailures() {
        return maxFailures;
    }

    public void setMaxFailures(int maxFailures) {
        this.maxFailures = maxFailures;
    }

    public Duration getLockDuration() {
        return lockDuration;
    }

    public void setLockDuration(Duration lockDuration) {
        this.lockDuration = lockDuration;
    }

    public Duration getSessionTtl() {
        return sessionTtl;
    }

    public void setSessionTtl(Duration sessionTtl) {
        this.sessionTtl = sessionTtl;
    }

    public boolean isAllowConcurrentSessions() {
        return allowConcurrentSessions;
    }

    public void setAllowConcurrentSessions(boolean allowConcurrentSessions) {
        this.allowConcurrentSessions = allowConcurrentSessions;
    }

    public String getStateFile() {
        return stateFile;
    }

    public void setStateFile(String stateFile) {
        this.stateFile = stateFile;
    }

    public Duration getPersistInterval() {
        return persistInterval;
    }

    public void setPersistInterval(Duration persistInterval) {
        this.persistInterval = persistInterval;
    }
}
