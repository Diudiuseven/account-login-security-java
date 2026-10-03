package com.github.diudiuseven.accountloginsecurityjava.security;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 信息泄露防护：不存在的账号、错误口令、已锁定、已封禁四种登录失败
 * 在错误内容与响应耗时上不得泄露账号是否存在；
 * 内部审计保留真实原因以便追溯，但不含口令。
 */
class InformationLeakTest {

    private record FailureOutcome(AuthFailureReason reason, String message) {
    }

    private FailureOutcome failLogin(AuthService auth, String account, char[] pw, String source) {
        AuthException e = assertThrows(AuthException.class,
                () -> auth.login(account, pw, "d", source));
        return new FailureOutcome(e.getReason(), e.getMessage());
    }

    @Test
    void fourFailureModesIndistinguishableInErrorContent() {
        TestStack stack = TestStack.create();
        stack.authService.register("known", "right-pw".toCharArray(), Set.of());
        stack.authService.register("locked", "right-pw".toCharArray(), Set.of());
        stack.authService.register("banned", "right-pw".toCharArray(), Set.of());
        stack.authService.register("admin", "a-pw".toCharArray(), Set.of(AuthService.ROLE_ADMIN));

        // 制造锁定账号
        for (int i = 0; i < 3; i++) {
            failLogin(stack.authService, "locked", "bad".toCharArray(), "src-lock");
        }
        // 制造封禁账号
        SessionRecord admin = stack.authService.login("admin", "a-pw".toCharArray(), "d", "s");
        stack.authService.ban(admin.token(), "banned");

        FailureOutcome unknown = failLogin(stack.authService, "no-such-account", "any".toCharArray(), "src-a");
        FailureOutcome wrongPw = failLogin(stack.authService, "known", "bad-pw".toCharArray(), "src-b");
        FailureOutcome locked = failLogin(stack.authService, "locked", "right-pw".toCharArray(), "src-lock");
        FailureOutcome banned = failLogin(stack.authService, "banned", "right-pw".toCharArray(), "src-c");

        // 四种失败的原因码与消息完全一致
        assertEquals(unknown, wrongPw);
        assertEquals(wrongPw, locked);
        assertEquals(locked, banned);
        assertEquals(AuthFailureReason.INVALID_CREDENTIALS, unknown.reason());
        assertEquals("invalid credentials", unknown.message());
    }

    @Test
    void loginTimingUniformAcrossFailureModes() {
        TestStack stack = TestStack.create();
        stack.authService.register("known", "right-pw".toCharArray(), Set.of());
        stack.authService.register("banned2", "right-pw".toCharArray(), Set.of());
        stack.authService.register("admin", "a-pw".toCharArray(), Set.of(AuthService.ROLE_ADMIN));
        SessionRecord admin = stack.authService.login("admin", "a-pw".toCharArray(), "d", "s");
        stack.authService.ban(admin.token(), "banned2");

        // 预热
        for (int i = 0; i < 30; i++) {
            failLoginQuiet(stack.authService, "known", "src-t1");
            failLoginQuiet(stack.authService, "ghost", "src-t2");
            failLoginQuiet(stack.authService, "banned2", "src-t3");
        }
        long wrongPw = measure(stack.authService, "known", "src-t1");
        long unknown = measure(stack.authService, "ghost", "src-t2");
        long banned = measure(stack.authService, "banned2", "src-t3");

        long max = Math.max(wrongPw, Math.max(unknown, banned));
        long min = Math.min(wrongPw, Math.min(unknown, banned));
        double ratio = (double) max / Math.max(1, min);
        assertTrue(ratio < 2.0, String.format(
                "失败耗时不应泄露账号状态: wrongPw=%dns unknown=%dns banned=%dns",
                wrongPw, unknown, banned));
    }

    private void failLoginQuiet(AuthService auth, String account, String source) {
        try {
            auth.login(account, "probe".toCharArray(), "d", source);
        } catch (AuthException ignored) {
            // 预期失败
        }
    }

    private long measure(AuthService auth, String account, String source) {
        long start = System.nanoTime();
        for (int i = 0; i < 100; i++) {
            failLoginQuiet(auth, account, source);
        }
        return (System.nanoTime() - start) / 100;
    }

    @Test
    void auditTrailKeepsRealReasonWithoutLeakingToCaller() {
        TestStack stack = TestStack.create();
        stack.authService.register("known", "right-pw".toCharArray(), Set.of());
        stack.authService.register("admin", "a-pw".toCharArray(), Set.of(AuthService.ROLE_ADMIN));
        SessionRecord admin = stack.authService.login("admin", "a-pw".toCharArray(), "d", "s");
        stack.authService.ban(admin.token(), "known");

        // 用正确口令登录被封禁账号：对外仍是统一错误，审计应记录 banned
        try {
            stack.authService.login("known", "right-pw".toCharArray(), "d", "src-audit");
        } catch (AuthException ignored) {
            // 预期失败
        }

        // 审计中有真实原因（banned），且任何事件都不含口令
        List<AuditLog.Event> denied = new ArrayList<>(stack.audit.eventsByAction("login"));
        assertTrue(denied.stream().anyMatch(e -> "banned".equals(e.detail())),
                "审计应保留真实失败原因以便追溯");
        for (AuditLog.Event e : stack.audit.events()) {
            String blob = e.action() + e.actor() + e.target() + e.outcome() + e.detail();
            assertTrue(!blob.contains("right-pw") && !blob.contains("a-pw"),
                    "审计事件不得包含口令");
        }
    }

    @Test
    void forbiddenAttemptsAreAuditedWithActorAndTarget() {
        TestStack stack = TestStack.create();
        stack.authService.register("admin", "a-pw".toCharArray(), Set.of(AuthService.ROLE_ADMIN));
        stack.authService.register("mallory", "m-pw".toCharArray(), Set.of());
        SessionRecord mallory = stack.authService.login("mallory", "m-pw".toCharArray(), "d", "s");

        assertThrows(AuthException.class, () ->
                stack.authService.resetPassword(mallory.token(), "admin", "hacked".toCharArray()));

        boolean traced = stack.audit.events().stream().anyMatch(e ->
                "reset-password".equals(e.action())
                        && "mallory".equals(e.actor())
                        && "admin".equals(e.target())
                        && "denied".equals(e.outcome()));
        assertTrue(traced, "越权请求必须可追溯（行为者/目标/结果）");
    }
}
