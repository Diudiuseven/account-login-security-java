package com.github.diudiuseven.accountloginsecurityjava.security;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 凭据安全：摘要不可逆、常数时间校验、明文不落盘、错误信息不含敏感内容。
 */
class CredentialSecurityTest {

    @TempDir
    Path tempDir;

    @Test
    void passwordStoredOnlyAsIrreversibleDigest() {
        TestStack stack = TestStack.create();
        stack.authService.register("alice", "s3cret!".toCharArray(), Set.of());

        CredentialStore.AccountRecord record = stack.credentials.find("alice");
        assertNotEquals(null, record);
        assertFalse(record.passwordHash().contains("s3cret!"));
        assertTrue(record.passwordHash().startsWith("1000:"), "摘要编码应含迭代次数");
        assertTrue(stack.hasher.verify("s3cret!".toCharArray(), record.passwordHash()));
        assertFalse(stack.hasher.verify("wrong".toCharArray(), record.passwordHash()));
    }

    @Test
    void samePasswordProducesDifferentSalts() {
        TestStack stack = TestStack.create();
        String h1 = stack.hasher.hash("same".toCharArray());
        String h2 = stack.hasher.hash("same".toCharArray());
        assertNotEquals(h1, h2, "相同口令应因随机盐产生不同摘要");
    }

    @Test
    void plaintextNeverPersistedToStateFile() throws Exception {
        String stateFile = tempDir.resolve("state.json").toString();
        TestStack stack = TestStack.create(stateFile);
        stack.authService.register("bob", "top-secret-plaintext".toCharArray(), Set.of());
        stack.flush();
        stack.shutdown();

        String content = Files.readString(Path.of(stateFile));
        assertFalse(content.contains("top-secret-plaintext"), "明文口令不得落盘");
        assertTrue(content.contains("bob"), "账号元数据应持久化");
    }

    @Test
    void exceptionMessagesContainNoSensitiveInfo() {
        TestStack stack = TestStack.create();
        stack.authService.register("carol", "pw123456".toCharArray(), Set.of());
        AuthException e = assertThrows(AuthException.class, () ->
                stack.authService.login("carol", "pw123456-wrong".toCharArray(), "d1", "src"));
        assertFalse(e.getMessage().contains("pw123456"), "错误信息不得含口令");
        assertFalse(e.getMessage().toLowerCase().contains("exist"), "错误信息不得暗示账号存在性");
        assertEquals(AuthFailureReason.INVALID_CREDENTIALS, e.getReason());
    }

    @Test
    void verifyTimingUniformBetweenKnownAndUnknownAccounts() {
        TestStack stack = TestStack.create();
        stack.authService.register("dave", "timing-probe".toCharArray(), Set.of());

        // 预热 JIT
        for (int i = 0; i < 50; i++) {
            stack.credentials.verify("dave", "x".toCharArray());
            stack.credentials.verify("nobody", "x".toCharArray());
        }
        long known = measure(stack, "dave");
        long unknown = measure(stack, "nobody");
        double ratio = (double) Math.max(known, unknown) / Math.max(1, Math.min(known, unknown));
        assertTrue(ratio < 2.0,
                "已知/未知账号校验耗时不应有量级差异, known=" + known + "ns unknown=" + unknown + "ns");
    }

    private long measure(TestStack stack, String account) {
        long start = System.nanoTime();
        for (int i = 0; i < 200; i++) {
            stack.credentials.verify(account, "probe".toCharArray());
        }
        return (System.nanoTime() - start) / 200;
    }
}
