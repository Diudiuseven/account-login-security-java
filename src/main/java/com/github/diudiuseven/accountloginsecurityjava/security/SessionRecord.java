package com.github.diudiuseven.accountloginsecurityjava.security;

/**
 * 会话记录。token 为不透明随机串；status 区分活跃/注销/被顶替/被失效。
 */
public record SessionRecord(String token, String accountId, String deviceId,
                            long issuedAt, long expiresAt,
                            long credentialVersion, Status status) {

    public enum Status {
        ACTIVE, REVOKED, SUPERSEDED, INVALIDATED
    }

    public SessionRecord withStatus(Status newStatus) {
        return new SessionRecord(token, accountId, deviceId, issuedAt, expiresAt,
                credentialVersion, newStatus);
    }

    public SessionRecord withExpiry(long newExpiresAt) {
        return new SessionRecord(token, accountId, deviceId, issuedAt, newExpiresAt,
                credentialVersion, status);
    }
}
