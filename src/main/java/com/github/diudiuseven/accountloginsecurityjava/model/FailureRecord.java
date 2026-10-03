package com.github.diudiuseven.accountloginsecurityjava.model;

/** 登录失败计数记录（按账号或来源 IP 维度）。 */
public class FailureRecord {

    public enum Kind { ACCOUNT, IP }

    private String key;
    private Kind kind;
    private int count;
    private long windowStart;
    private long lockedUntil;

    public FailureRecord() {
    }

    public String getKey() { return key; }
    public void setKey(String key) { this.key = key; }
    public Kind getKind() { return kind; }
    public void setKind(Kind kind) { this.kind = kind; }
    public int getCount() { return count; }
    public void setCount(int count) { this.count = count; }
    public long getWindowStart() { return windowStart; }
    public void setWindowStart(long windowStart) { this.windowStart = windowStart; }
    public long getLockedUntil() { return lockedUntil; }
    public void setLockedUntil(long lockedUntil) { this.lockedUntil = lockedUntil; }
}
