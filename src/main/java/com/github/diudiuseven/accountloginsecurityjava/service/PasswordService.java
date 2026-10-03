package com.github.diudiuseven.accountloginsecurityjava.service;

import com.github.diudiuseven.accountloginsecurityjava.config.SecurityProperties;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Base64;

/**
 * 口令服务：只保存不可逆摘要（PBKDF2WithHmacSHA256 + 每口令随机盐）。
 * 明文口令不落盘、不进日志、不出现在任何异常信息中。
 */
@Service
public class PasswordService {

    private static final String ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final int SALT_BYTES = 16;
    private static final int HASH_BITS = 256;
    private static final String PREFIX = "pbkdf2_sha256";

    private final SecurityProperties properties;
    private final SecureRandom random = new SecureRandom();

    /** 启动时预生成一个哑摘要，用于“账号不存在”时拉平校验耗时，避免枚举。 */
    private volatile String dummyHash;

    public PasswordService(SecurityProperties properties) {
        this.properties = properties;
    }

    /** 对明文口令生成不可逆摘要。 */
    public String hash(String rawPassword) {
        if (rawPassword == null || rawPassword.isEmpty()) {
            throw new IllegalArgumentException("password must not be empty");
        }
        byte[] salt = new byte[SALT_BYTES];
        random.nextBytes(salt);
        byte[] derived = pbkdf2(rawPassword.toCharArray(), salt, properties.getPasswordHashIterations());
        return PREFIX + "$" + properties.getPasswordHashIterations()
                + "$" + Base64.getEncoder().encodeToString(salt)
                + "$" + Base64.getEncoder().encodeToString(derived);
    }

    /** 常量时间校验明文口令与摘要是否匹配。 */
    public boolean matches(String rawPassword, String storedHash) {
        if (rawPassword == null || storedHash == null) {
            return false;
        }
        try {
            String[] parts = storedHash.split("\\$");
            if (parts.length != 4 || !PREFIX.equals(parts[0])) {
                return false;
            }
            int iterations = Integer.parseInt(parts[1]);
            byte[] salt = Base64.getDecoder().decode(parts[2]);
            byte[] expected = Base64.getDecoder().decode(parts[3]);
            byte[] actual = pbkdf2(rawPassword.toCharArray(), salt, iterations);
            return MessageDigest.isEqual(expected, actual);
        } catch (Exception e) {
            // 任何解析/计算异常都按“不匹配”处理，异常信息不含明文口令
            return false;
        }
    }

    /**
     * 返回一个与真实摘要等长的哑摘要。
     * 账号不存在时仍执行一次完整 PBKDF2，使响应耗时与“口令错误”一致。
     */
    public String dummyHash() {
        if (dummyHash == null) {
            synchronized (this) {
                if (dummyHash == null) {
                    dummyHash = hash("dummy-password-for-timing-equalization");
                }
            }
        }
        return dummyHash;
    }

    private byte[] pbkdf2(char[] password, byte[] salt, int iterations) {
        try {
            KeySpec spec = new PBEKeySpec(password, salt, iterations, HASH_BITS);
            SecretKeyFactory factory = SecretKeyFactory.getInstance(ALGORITHM);
            return factory.generateSecret(spec).getEncoded();
        } catch (Exception e) {
            throw new IllegalStateException("password digest computation failed", e);
        }
    }
}
