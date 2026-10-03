package com.github.diudiuseven.accountloginsecurityjava.security;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 会话签发/续期/注销与多端顶替：被顶替与被注销的会话立即失效，
 * 拒绝原因可区分。
 */
class SessionLifecycleTest {

    @Test
    void supersedePolicyKicksOldSessionImmediately() {
        TestStack stack = TestStack.create(); // allowConcurrentSessions=false
        stack.authService.register("alice", "pw".toCharArray(), Set.of());

        SessionRecord first = stack.authService.login("alice", "pw".toCharArray(), "phone", "s");
        SessionRecord second = stack.authService.login("alice", "pw".toCharArray(), "pc", "s");
        assertNotEquals(first.token(), second.token());

        // 旧会话立即失效，原因可区分为 SUPERSEDED
        AuthException e = assertThrows(AuthException.class,
                () -> stack.authService.requireAccount(first.token()));
        assertEquals(AuthFailureReason.SESSION_SUPERSEDED, e.getReason());
        // 新会话可用
        assertEquals("alice", stack.authService.requireAccount(second.token()));
    }

    @Test
    void coexistPolicyKeepsBothSessions() {
        SecurityProperties p = TestStack.fastProperties("");
        p.setAllowConcurrentSessions(true);
        TestStack stack = new TestStack(p);
        stack.authService.register("bob", "pw".toCharArray(), Set.of());

        SessionRecord s1 = stack.authService.login("bob", "pw".toCharArray(), "phone", "s");
        SessionRecord s2 = stack.authService.login("bob", "pw".toCharArray(), "pc", "s");
        assertEquals("bob", stack.authService.requireAccount(s1.token()));
        assertEquals("bob", stack.authService.requireAccount(s2.token()));
    }

    @Test
    void revokedSessionRejectedWithDistinctReason() {
        TestStack stack = TestStack.create();
        stack.authService.register("carol", "pw".toCharArray(), Set.of());
        SessionRecord session = stack.authService.login("carol", "pw".toCharArray(), "d", "s");
        stack.authService.logout(session.token());

        AuthException e = assertThrows(AuthException.class,
                () -> stack.authService.requireAccount(session.token()));
        assertEquals(AuthFailureReason.SESSION_REVOKED, e.getReason());

        AuthException e2 = assertThrows(AuthException.class,
                () -> stack.authService.requireAccount("nonexistent-token"));
        assertEquals(AuthFailureReason.SESSION_INVALID, e2.getReason());
    }

    @Test
    void renewExtendsExpiryOnlyForActiveSession() {
        TestStack stack = TestStack.create();
        stack.authService.register("dave", "pw".toCharArray(), Set.of());
        SessionRecord session = stack.authService.login("dave", "pw".toCharArray(), "d", "s");
        SessionRecord renewed = stack.authService.renew(session.token());
        assertTrue(renewed.expiresAt() >= session.expiresAt());

        stack.authService.logout(session.token());
        AuthException e = assertThrows(AuthException.class,
                () -> stack.authService.renew(session.token()));
        assertEquals(AuthFailureReason.SESSION_REVOKED, e.getReason());
    }

    @Test
    void expiredSessionRejectedWithDistinctReason() throws Exception {
        SecurityProperties p = TestStack.fastProperties("");
        p.setSessionTtl(java.time.Duration.ofMillis(150));
        TestStack stack = new TestStack(p);
        stack.authService.register("erin", "pw".toCharArray(), Set.of());
        SessionRecord session = stack.authService.login("erin", "pw".toCharArray(), "d", "s");
        Thread.sleep(250);
        AuthException e = assertThrows(AuthException.class,
                () -> stack.authService.requireAccount(session.token()));
        assertEquals(AuthFailureReason.SESSION_EXPIRED, e.getReason());
    }

    @Test
    void concurrentSupersedeLeavesExactlyOneActiveSession() throws Exception {
        TestStack stack = TestStack.create();
        stack.authService.register("fred", "pw".toCharArray(), Set.of());

        int n = 16;
        ExecutorService pool = Executors.newFixedThreadPool(n);
        CountDownLatch go = new CountDownLatch(1);
        List<Future<SessionRecord>> futures = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            final int idx = i;
            futures.add(pool.submit(() -> {
                go.await();
                return stack.authService.login("fred", "pw".toCharArray(), "dev-" + idx, "s");
            }));
        }
        go.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(10, TimeUnit.SECONDS));

        int active = 0;
        for (Future<SessionRecord> f : futures) {
            SessionRecord s = f.get();
            try {
                stack.authService.requireAccount(s.token());
                active++;
            } catch (AuthException e) {
                assertEquals(AuthFailureReason.SESSION_SUPERSEDED, e.getReason(),
                        "被顶替的会话原因必须可区分");
            }
        }
        assertEquals(1, active, "顶替策略下并发登录最终只能有一个活跃会话");
    }
}
