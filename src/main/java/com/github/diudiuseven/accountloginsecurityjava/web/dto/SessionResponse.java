package com.github.diudiuseven.accountloginsecurityjava.web.dto;

/** 会话响应。 */
public class SessionResponse {
    private String token;
    private String username;
    private long issuedAt;
    private long expiresAt;
    private String status;
    private String device;
    private String ip;
    private String revokeReason;

    public String getToken() { return token; }
    public void setToken(String token) { this.token = token; }
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
    public long getIssuedAt() { return issuedAt; }
    public void setIssuedAt(long issuedAt) { this.issuedAt = issuedAt; }
    public long getExpiresAt() { return expiresAt; }
    public void setExpiresAt(long expiresAt) { this.expiresAt = expiresAt; }
    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }
    public String getDevice() { return device; }
    public void setDevice(String device) { this.device = device; }
    public String getIp() { return ip; }
    public void setIp(String ip) { this.ip = ip; }
    public String getRevokeReason() { return revokeReason; }
    public void setRevokeReason(String revokeReason) { this.revokeReason = revokeReason; }
}
