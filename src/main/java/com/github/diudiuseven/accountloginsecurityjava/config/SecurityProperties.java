package com.github.diudiuseven.accountloginsecurityjava.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * 安全相关配置项。
 */
@ConfigurationProperties(prefix = "security")
public class SecurityProperties {

    /** 持久化数据目录（进程内文件存储）。 */
    private String storeDir = "./data/security";

    /** PBKDF2 迭代次数。 */
    private int passwordHashIterations = 120_000;

    /** 登录失败计数窗口（毫秒）。 */
    private long failWindowMs = 10 * 60_000L;

    /** 窗口内允许的最大失败次数，超过即锁定。 */
    private int maxFailures = 5;

    /** 账号锁定时长（毫秒）。 */
    private long lockDurationMs = 15 * 60_000L;

    /** 来源 IP 失败计数窗口（毫秒）。 */
    private long ipFailWindowMs = 10 * 60_000L;

    /** 同一来源 IP 窗口内允许的最大失败次数。 */
    private int ipMaxFailures = 20;

    /** 会话有效期（毫秒）。 */
    private long sessionTtlMs = 30 * 60_000L;

    /** 多端会话策略：MULTI（并存）或 KICK_OUT（新登录顶替旧会话）。 */
    private String sessionStrategy = "KICK_OUT";

    /** 凭据变更（改密/重置）后是否吊销该账号全部会话。 */
    private boolean revokeOnCredentialChange = true;

    /** 重启后是否自动恢复未到期的会话（true=恢复，false=全部吊销）。 */
    private boolean restoreSessionsOnRestart = true;

    /** 引导管理员账号。 */
    private String bootstrapAdminUsername = "admin";
    private String bootstrapAdminPassword = "admin123";

    public String getStoreDir() { return storeDir; }
    public void setStoreDir(String storeDir) { this.storeDir = storeDir; }
    public int getPasswordHashIterations() { return passwordHashIterations; }
    public void setPasswordHashIterations(int passwordHashIterations) { this.passwordHashIterations = passwordHashIterations; }
    public long getFailWindowMs() { return failWindowMs; }
    public void setFailWindowMs(long failWindowMs) { this.failWindowMs = failWindowMs; }
    public int getMaxFailures() { return maxFailures; }
    public void setMaxFailures(int maxFailures) { this.maxFailures = maxFailures; }
    public long getLockDurationMs() { return lockDurationMs; }
    public void setLockDurationMs(long lockDurationMs) { this.lockDurationMs = lockDurationMs; }
    public long getIpFailWindowMs() { return ipFailWindowMs; }
    public void setIpFailWindowMs(long ipFailWindowMs) { this.ipFailWindowMs = ipFailWindowMs; }
    public int getIpMaxFailures() { return ipMaxFailures; }
    public void setIpMaxFailures(int ipMaxFailures) { this.ipMaxFailures = ipMaxFailures; }
    public long getSessionTtlMs() { return sessionTtlMs; }
    public void setSessionTtlMs(long sessionTtlMs) { this.sessionTtlMs = sessionTtlMs; }
    public String getSessionStrategy() { return sessionStrategy; }
    public void setSessionStrategy(String sessionStrategy) { this.sessionStrategy = sessionStrategy; }
    public boolean isRevokeOnCredentialChange() { return revokeOnCredentialChange; }
    public void setRevokeOnCredentialChange(boolean revokeOnCredentialChange) { this.revokeOnCredentialChange = revokeOnCredentialChange; }
    public boolean isRestoreSessionsOnRestart() { return restoreSessionsOnRestart; }
    public void setRestoreSessionsOnRestart(boolean restoreSessionsOnRestart) { this.restoreSessionsOnRestart = restoreSessionsOnRestart; }
    public String getBootstrapAdminUsername() { return bootstrapAdminUsername; }
    public void setBootstrapAdminUsername(String bootstrapAdminUsername) { this.bootstrapAdminUsername = bootstrapAdminUsername; }
    public String getBootstrapAdminPassword() { return bootstrapAdminPassword; }
    public void setBootstrapAdminPassword(String bootstrapAdminPassword) { this.bootstrapAdminPassword = bootstrapAdminPassword; }
}
