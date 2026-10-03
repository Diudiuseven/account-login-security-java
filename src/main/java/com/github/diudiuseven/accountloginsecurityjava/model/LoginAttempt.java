package com.github.diudiuseven.accountloginsecurityjava.model;

/**
 * 登录尝试记录。用于崩溃恢复时区分“未完成的登录”。
 * 状态机：PENDING -> SUCCESS / FAILURE / INTERRUPTED。
 */
public class LoginAttempt {

    public enum Status { PENDING, SUCCESS, FAILURE, INTERRUPTED }

    private String attemptId;
    private String username;
    private String ip;
    private long startedAt;
    private Status status;
    private String reason;
    private String sessionToken;

    public LoginAttempt() {
    }

    public String getAttemptId() { return attemptId; }
    public void setAttemptId(String attemptId) { this.attemptId = attemptId; }
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
    public String getIp() { return ip; }
    public void setIp(String ip) { this.ip = ip; }
    public long getStartedAt() { return startedAt; }
    public void setStartedAt(long startedAt) { this.startedAt = startedAt; }
    public Status getStatus() { return status; }
    public void setStatus(Status status) { this.status = status; }
    public String getReason() { return reason; }
    public void setReason(String reason) { this.reason = reason; }
    public String getSessionToken() { return sessionToken; }
    public void setSessionToken(String sessionToken) { this.sessionToken = sessionToken; }
}
