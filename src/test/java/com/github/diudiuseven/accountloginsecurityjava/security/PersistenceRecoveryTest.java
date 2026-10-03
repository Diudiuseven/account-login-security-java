package com.github.diudiuseven.accountloginsecurityjava.security;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 持久化与重启恢复：已注销会话不得复活，锁定不得超过既定到期时间，
 * 活跃会话与凭据可恢复，损坏文件可解释地降级为全新状态。
 */
class PersistenceRecoveryTest {

    @TempDir
    Path tempDir;

    private String stateFile() {
        return tempDir.resolve("state.json").toString();
    }

    @Test
    void revokedSessionStaysRevokedAfterRestart() {
        String file = stateFile();
        TestStack first = TestStack.create(file);
        first.authService.register("alice", "pw".toCharArray(), Set.of());
        SessionRecord session = first.authService.login("alice", "pw".toCharArray(), "d", "s");
        first.authService.logout(session.token());
        first.flush();
        first.shutdown();

        // 模拟进程重启：全新组件栈加载同一状态文件
        TestStack second = TestStack.create(file);
        AuthException e = assertThrows(AuthException.class,
                () -> second.authService.requireAccount(session.token()));
        assertEquals(AuthFailureReason.SESSION_REVOKED, e.getReason(),
                "重启后已注销会话不得复活，且原因可区分");
        second.shutdown();
    }

    @Test
    void activeSessionAndCredentialSurviveRestart() {
        String file = stateFile();
        TestStack first = TestStack.create(file);
        first.authService.register("bob", "pw".toCharArray(), Set.of());
        SessionRecord session = first.authService.login("bob", "pw".toCharArray(), "d", "s");
        first.flush();
        first.shutdown();

        TestStack second = TestStack.create(file);
        assertEquals("bob", second.authService.requireAccount(session.token()),
                "未到期活跃会话重启后应继续可用");
        // 凭据（摘要）恢复后可继续登录
        SessionRecord fresh = second.authService.login("bob", "pw".toCharArray(), "d2", "s");
        assertNotNull(fresh);
        second.shutdown();
    }

    @Test
    void lockNeverExceedsConfiguredExpiryAfterRestart() throws Exception {
        String file = stateFile();
        SecurityProperties p = TestStack.fastProperties(file);
        p.setLockDuration(Duration.ofMillis(400));
        TestStack first = new TestStack(p);
        first.authService.register("carol", "pw".toCharArray(), Set.of());
        for (int i = 0; i < 3; i++) {
            assertThrows(AuthException.class, () ->
                    first.authService.login("carol", "bad".toCharArray(), "d", "s"));
        }
        assertTrue(first.lockout.isLocked("carol", "s"));
        first.flush();
        first.shutdown();

        // 重启期间锁到期：恢复后不得继续锁定
        Thread.sleep(500);
        TestStack second = TestStack.create(file);
        assertFalse(second.lockout.isLocked("carol", "s"),
                "重启后锁定不得超过既定到期时间");
        SessionRecord session = second.authService.login("carol", "pw".toCharArray(), "d", "s");
        assertEquals("carol", session.accountId());
        second.shutdown();
    }

    @Test
    void unexpiredLockSurvivesRestart() {
        String file = stateFile();
        SecurityProperties p = TestStack.fastProperties(file);
        p.setLockDuration(Duration.ofSeconds(30));
        TestStack first = new TestStack(p);
        first.authService.register("dave", "pw".toCharArray(), Set.of());
        for (int i = 0; i < 3; i++) {
            assertThrows(AuthException.class, () ->
                    first.authService.login("dave", "bad".toCharArray(), "d", "s"));
        }
        first.flush();
        first.shutdown();

        TestStack second = TestStack.create(file);
        assertTrue(second.lockout.isLocked("dave", "s"), "未到期锁定重启后应继续生效");
        assertThrows(AuthException.class, () ->
                second.authService.login("dave", "pw".toCharArray(), "d", "s"));
        second.shutdown();
    }

    @Test
    void banStateSurvivesRestart() {
        String file = stateFile();
        TestStack first = TestStack.create(file);
        first.authService.register("admin", "a-pw".toCharArray(), Set.of(AuthService.ROLE_ADMIN));
        first.authService.register("eve", "e-pw".toCharArray(), Set.of());
        SessionRecord admin = first.authService.login("admin", "a-pw".toCharArray(), "d", "s");
        first.authService.ban(admin.token(), "eve");
        first.flush();
        first.shutdown();

        TestStack second = TestStack.create(file);
        AuthException e = assertThrows(AuthException.class, () ->
                second.authService.login("eve", "e-pw".toCharArray(), "d", "s"));
        assertEquals(AuthFailureReason.INVALID_CREDENTIALS, e.getReason(),
                "重启后封禁状态应继续生效且错误内容不泄露原因");
        second.shutdown();
    }

    @Test
    void corruptedStateFileDegradesToFreshStart() throws Exception {
        String file = stateFile();
        Files.writeString(Path.of(file), "{ not valid json !!!");
        TestStack stack = TestStack.create(file);
        // 可解释地降级：视为全新状态，服务可用
        stack.authService.register("frank", "pw".toCharArray(), Set.of());
        SessionRecord session = stack.authService.login("frank", "pw".toCharArray(), "d", "s");
        assertEquals("frank", session.accountId());
        stack.shutdown();
    }

    @Test
    void missingStateFileMeansFreshStart() {
        TestStack stack = TestStack.create(stateFile());
        assertNull(stack.stateStore.load());
        stack.shutdown();
    }

    @Test
    void stateFileContainsNoPlaintextAndIsAtomic() throws Exception {
        String file = stateFile();
        TestStack stack = TestStack.create(file);
        stack.authService.register("grace", "never-persisted-plaintext".toCharArray(), Set.of());
        SessionRecord s = stack.authService.login("grace", "never-persisted-plaintext".toCharArray(), "d", "s");
        stack.flush();
        stack.shutdown();

        String content = Files.readString(Path.of(file));
        assertFalse(content.contains("never-persisted-plaintext"));
        // 文件是完整 JSON（原子 rename 保证不会读到写了一半的内容）
        Map<?, ?> parsed = new com.fasterxml.jackson.databind.ObjectMapper()
                .readValue(content, Map.class);
        assertTrue(parsed.containsKey("accounts"));
        assertTrue(parsed.containsKey("sessions"));
        assertTrue(parsed.containsKey("lockout"));
        assertNotNull(s);
    }
}
