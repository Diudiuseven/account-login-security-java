package com.github.diudiuseven.accountloginsecurityjava.model;

/** 安全审计事件（追加写，跨重启保留）。 */
public class AuditEvent {

    private long timestamp;
    private String eventType;
    private String username;
    private String ip;
    private String detail;
    private String result;

    public AuditEvent() {
    }

    public long getTimestamp() { return timestamp; }
    public void setTimestamp(long timestamp) { this.timestamp = timestamp; }
    public String getEventType() { return eventType; }
    public void setEventType(String eventType) { this.eventType = eventType; }
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
    public String getIp() { return ip; }
    public void setIp(String ip) { this.ip = ip; }
    public String getDetail() { return detail; }
    public void setDetail(String detail) { this.detail = detail; }
    public String getResult() { return result; }
    public void setResult(String result) { this.result = result; }
}
