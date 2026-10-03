package com.github.diudiuseven.accountloginsecurityjava.model;

/** 会话实体。 */
public class Session {

    private String token;
    private String username;
    private long issuedAt;
    private long expiresAt;
    private SessionStatus status;
    private String device;
    private String ip;
    /** 吊销原因（REVOKED 时非空），用于区分被顶替/注销/封禁等。 */
    private String revokeReason;

    public Session() {
    }

    public String getToken() { return token; }
    public void setToken(String token) { this.token = token; }
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
    public long getIssuedAt() { return issuedAt; }
    public void setIssuedAt(long issuedAt) { this.issuedAt = issuedAt; }
    public long getExpiresAt() { return expiresAt; }
    public void setExpiresAt(long expiresAt) { this.expiresAt = expiresAt; }
    public SessionStatus getStatus() { return status; }
    public void setStatus(SessionStatus status) { this.status = status; }
    public String getDevice() { return device; }
    public void setDevice(String device) { this.device = device; }
    public String getIp() { return ip; }
    public void setIp(String ip) { this.ip = ip; }
    public String getRevokeReason() { return revokeReason; }
    public void setRevokeReason(String revokeReason) { this.revokeReason = revokeReason; }
}
