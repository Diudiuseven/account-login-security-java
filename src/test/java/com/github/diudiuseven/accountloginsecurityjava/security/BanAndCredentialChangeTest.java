package com.github.diudiuseven.accountloginsecurityjava.security;

import java.util.Set;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * 凭据变更、口令重置、封禁与解封：敏感操作后相关会话按策略失效，
 * 封禁期间登录全部拒绝，解封后不得沿用封禁前签发的会话。
 */
class BanAndCredentialChangeTest {

    private TestStack stackWithAdminAndUser() {
        TestStack stack = TestStack.create();
        stack.authService.register("admin", "admin-pw".toCharArray(), Set.of(AuthService.ROLE_ADMIN));
        stack.authService.register("user", "user-pw".toCharArray(), Set.of());
        return stack;
    }

    @Test
    void bannedAccountLoginRejectedAndSessionKilled() {
        TestStack stack = stackWithAdminAndUser();
        SessionRecord admin = stack.authService.login("admin", "admin-pw".toCharArray(), "d", "s");
        SessionRecord user = stack.authService.login("user", "user-pw".toCharArray(), "d", "s");

        stack.authService.ban(admin.token(), "user");

        // 既有会话立即失效
        AuthException e = assertThrows(AuthException.class,
                () -> stack.authService.requireAccount(user.token()));
        assertEquals(AuthFailureReason.SESSION_INVALIDATED, e.getReason());

        // 封禁期间登录（即使口令正确）被拒绝，错误内容与口令错误一致
        AuthException e2 = assertThrows(AuthException.class, () ->
                stack.authService.login("user", "user-pw".toCharArray(), "d", "s"));
        assertEquals(AuthFailureReason.INVALID_CREDENTIALS, e2.getReason());
        assertEquals("invalid credentials", e2.getMessage());
    }

    @Test
    void unbanDoesNotResurrectPreBanSessions() {
        TestStack stack = stackWithAdminAndUser();
        SessionRecord admin = stack.authService.login("admin", "admin-pw".toCharArray(), "d", "s");
        SessionRecord preBan = stack.authService.login("user", "user-pw".toCharArray(), "d", "s");

        stack.authService.ban(admin.token(), "user");
        stack.authService.unban(admin.token(), "user");

        // 封禁前签发的会话不得复活
        AuthException e = assertThrows(AuthException.class,
                () -> stack.authService.requireAccount(preBan.token()));
        assertEquals(AuthFailureReason.SESSION_INVALIDATED, e.getReason());

        // 解封后可重新登录
        SessionRecord fresh = stack.authService.login("user", "user-pw".toCharArray(), "d", "s");
        assertEquals("user", stack.authService.requireAccount(fresh.token()));
    }

    @Test
    void changePasswordInvalidatesAllSessions() {
        TestStack stack = stackWithAdminAndUser();
        SessionRecord s1 = stack.authService.login("user", "user-pw".toCharArray(), "phone", "s");

        stack.authService.changePassword(s1.token(), "user-pw".toCharArray(), "new-pw".toCharArray());

        AuthException e = assertThrows(AuthException.class,
                () -> stack.authService.requireAccount(s1.token()));
        assertEquals(AuthFailureReason.SESSION_INVALIDATED, e.getReason());

        // 旧口令失效，新口令可登录
        assertThrows(AuthException.class, () ->
                stack.authService.login("user", "user-pw".toCharArray(), "d", "s2"));
        SessionRecord s2 = stack.authService.login("user", "new-pw".toCharArray(), "d", "s2");
        assertEquals("user", s2.accountId());
    }

    @Test
    void changePasswordRequiresCorrectOldPassword() {
        TestStack stack = stackWithAdminAndUser();
        SessionRecord s1 = stack.authService.login("user", "user-pw".toCharArray(), "d", "s");
        AuthException e = assertThrows(AuthException.class, () ->
                stack.authService.changePassword(s1.token(), "wrong-old".toCharArray(), "new".toCharArray()));
        assertEquals(AuthFailureReason.INVALID_CREDENTIALS, e.getReason());
        // 旧口令仍有效
        assertEquals("user", stack.authService.requireAccount(s1.token()));
    }

    @Test
    void adminResetInvalidatesTargetSessions() {
        TestStack stack = stackWithAdminAndUser();
        SessionRecord admin = stack.authService.login("admin", "admin-pw".toCharArray(), "d", "s");
        SessionRecord user = stack.authService.login("user", "user-pw".toCharArray(), "d", "s");

        stack.authService.resetPassword(admin.token(), "user", "reset-pw".toCharArray());

        AuthException e = assertThrows(AuthException.class,
                () -> stack.authService.requireAccount(user.token()));
        assertEquals(AuthFailureReason.SESSION_INVALIDATED, e.getReason());

        SessionRecord fresh = stack.authService.login("user", "reset-pw".toCharArray(), "d", "s2");
        assertEquals("user", fresh.accountId());
    }

    @Test
    void nonAdminCannotResetBanOrUnban() {
        TestStack stack = stackWithAdminAndUser();
        SessionRecord user = stack.authService.login("user", "user-pw".toCharArray(), "d", "s");

        AuthException e1 = assertThrows(AuthException.class, () ->
                stack.authService.resetPassword(user.token(), "admin", "x".toCharArray()));
        assertEquals(AuthFailureReason.FORBIDDEN, e1.getReason());

        AuthException e2 = assertThrows(AuthException.class, () ->
                stack.authService.ban(user.token(), "admin"));
        assertEquals(AuthFailureReason.FORBIDDEN, e2.getReason());

        AuthException e3 = assertThrows(AuthException.class, () ->
                stack.authService.unban(user.token(), "admin"));
        assertEquals(AuthFailureReason.FORBIDDEN, e3.getReason());

        // 越权尝试必须可追溯
        long denied = stack.audit.events().stream()
                .filter(ev -> "denied".equals(ev.outcome()) && "forbidden".equals(ev.detail()))
                .count();
        assertEquals(3, denied, "三次越权尝试都应留审计痕迹");
        // 目标账号未受影响
        assertEquals("admin", stack.authService.requireAccount(
                stack.authService.login("admin", "admin-pw".toCharArray(), "d", "s2").token()));
    }

    @Test
    void sensitiveOpsRequireValidSession() {
        TestStack stack = stackWithAdminAndUser();
        AuthException e = assertThrows(AuthException.class, () ->
                stack.authService.ban("bogus-token", "user"));
        assertEquals(AuthFailureReason.SESSION_INVALID, e.getReason());
    }
}
