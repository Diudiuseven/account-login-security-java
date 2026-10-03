package com.github.diudiuseven.accountloginsecurityjava.security;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Base64;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import org.springframework.stereotype.Component;

/**
 * 口令不可逆摘要（PBKDF2-HmacSHA256）。
 * 编码格式：iterations:saltBase64:hashBase64。
 * 只输出/校验摘要，明文不落盘、不进日志、不进异常。
 */
@Component
public class PasswordHasher {

    private static final String ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final int SALT_BYTES = 16;
    private static final int KEY_BITS = 256;

    private final SecurityProperties properties;
    private final SecureRandom random = new SecureRandom();

    public PasswordHasher(SecurityProperties properties) {
        this.properties = properties;
    }

    /** 生成随机盐并计算摘要，返回可持久化的编码串。 */
    public String hash(char[] password) {
        byte[] salt = new byte[SALT_BYTES];
        random.nextBytes(salt);
        byte[] derived = derive(password, salt, properties.getHashIterations());
        return properties.getHashIterations() + ":"
                + Base64.getEncoder().encodeToString(salt) + ":"
                + Base64.getEncoder().encodeToString(derived);
    }

    /** 常数时间校验：摘要比较使用 MessageDigest.isEqual，避免时序泄露。 */
    public boolean verify(char[] password, String encoded) {
        try {
            String[] parts = encoded.split(":");
            if (parts.length != 3) {
                return false;
            }
            int iterations = Integer.parseInt(parts[0]);
            byte[] salt = Base64.getDecoder().decode(parts[1]);
            byte[] expected = Base64.getDecoder().decode(parts[2]);
            byte[] actual = derive(password, salt, iterations);
            return MessageDigest.isEqual(expected, actual);
        } catch (RuntimeException e) {
            return false;
        }
    }

    private byte[] derive(char[] password, byte[] salt, int iterations) {
        try {
            KeySpec spec = new PBEKeySpec(password, salt, iterations, KEY_BITS);
            return SecretKeyFactory.getInstance(ALGORITHM).generateSecret(spec).getEncoded();
        } catch (Exception e) {
            // 算法不可用属环境错误，不携带任何口令信息
            throw new IllegalStateException("password hash algorithm unavailable");
        }
    }
}
