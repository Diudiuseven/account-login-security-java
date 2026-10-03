package com.github.diudiuseven.accountloginsecurityjava.security;

import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.stereotype.Component;

/**
 * 账号凭据存储：只保存不可逆摘要与账号元数据（角色、封禁状态、凭据版本）。
 * 校验时对不存在的账号执行等耗时的哑运算，避免通过耗时差异探测账号是否存在。
 */
@Component
public class CredentialStore {

    /** 账号记录。passwordHash 只保存摘要编码，绝不保存明文。 */
    public record AccountRecord(String accountId, String passwordHash,
                                Set<String> roles, boolean banned,
                                long credentialVersion) {
    }

    private final PasswordHasher hasher;
    private final Map<String, AccountRecord> accounts = new ConcurrentHashMap<>();

    /** 哑摘要：账号不存在时对其执行 verify，保证耗时与真实账号一致。 */
    private final String dummyHash;

    public CredentialStore(PasswordHasher hasher) {
        this.hasher = hasher;
        this.dummyHash = hasher.hash("dummy-password-for-uniform-timing".toCharArray());
    }

    /** 设置/覆盖账号凭据；凭据版本递增，封禁状态保留。 */
    public void setCredential(String accountId, char[] password, Set<String> roles) {
        String encoded = hasher.hash(password);
        accounts.compute(accountId, (id, old) -> new AccountRecord(
                id, encoded,
                roles != null ? Set.copyOf(roles) : (old != null ? old.roles() : Set.of()),
                old != null && old.banned(),
                old != null ? old.credentialVersion() + 1 : 1L));
    }

    /** 常数时间校验口令；账号不存在时也执行等耗时运算。 */
    public boolean verify(String accountId, char[] password) {
        AccountRecord record = accounts.get(accountId);
        String encoded = record != null ? record.passwordHash() : dummyHash;
        boolean ok = hasher.verify(password, encoded);
        return ok && record != null;
    }

    public AccountRecord find(String accountId) {
        return accounts.get(accountId);
    }

    public void setBanned(String accountId, boolean banned) {
        accounts.computeIfPresent(accountId, (id, old) -> new AccountRecord(
                id, old.passwordHash(), old.roles(), banned, old.credentialVersion()));
    }

    /** 凭据版本号，每次改密/重置递增，用于使旧会话失效。 */
    public long credentialVersion(String accountId) {
        AccountRecord record = accounts.get(accountId);
        return record != null ? record.credentialVersion() : 0L;
    }

    public Map<String, AccountRecord> snapshot() {
        return Map.copyOf(accounts);
    }

    public void restore(Map<String, AccountRecord> records) {
        accounts.clear();
        accounts.putAll(records);
    }
}
