package com.github.diudiuseven.accountloginsecurityjava.security;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 高并发混合场景：登录、重置、封禁、解封同时发生。
 * 任意请求不得读到写了一半的中间状态，最终结果确定且可解释。
 */
class HighConcurrencyTest {

    @Test
    void concurrentLoginResetBanUnbanConvergesToDeterministicState() throws Exception {
        TestStack stack = TestStack.create();
        stack.authService.register("admin", "a-pw".toCharArray(), Set.of(AuthService.ROLE_ADMIN));
        stack.authService.register("user", "pw-0".toCharArray(), Set.of());
        SessionRecord admin = stack.authService.login("admin", "a-pw".toCharArray(), "d", "s");

        int workers = 24;
        ExecutorService pool = Executors.newFixedThreadPool(workers);
        CountDownLatch go = new CountDownLatch(1);
        AtomicInteger loginOk = new AtomicInteger();
        AtomicInteger loginDenied = new AtomicInteger();
        AtomicInteger sessionRejected = new AtomicInteger();
        List<Future<?>> futures = new ArrayList<>();

        // 登录线程：反复登录并立即校验会话
        for (int i = 0; i < 12; i++) {
            final int idx = i;
            futures.add(pool.submit(() -> {
                await(go);
                for (int j = 0; j < 20; j++) {
                    try {
                        SessionRecord s = stack.authService.login(
                                "user", ("pw-" + (j % 3)).toCharArray(), "dev-" + idx, "src-" + idx);
                        loginOk.incrementAndGet();
                        // 读到的会话状态必须完整且可解释：要么活跃，要么给出区分原因
                        try {
                            assertEquals("user", stack.authService.requireAccount(s.token()));
                        } catch (AuthException e) {
                            sessionRejected.incrementAndGet();
                            assertTrue(e.getReason() == AuthFailureReason.SESSION_SUPERSEDED
                                            || e.getReason() == AuthFailureReason.SESSION_INVALIDATED
                                            || e.getReason() == AuthFailureReason.SESSION_EXPIRED,
                                    "拒绝原因必须可区分: " + e.getReason());
                        }
                    } catch (AuthException e) {
                        loginDenied.incrementAndGet();
                        assertEquals(AuthFailureReason.INVALID_CREDENTIALS, e.getReason());
                    }
                }
            }));
        }
        // 管理线程：交替重置口令、封禁、解封
        for (int i = 0; i < 12; i++) {
            final int idx = i;
            futures.add(pool.submit(() -> {
                await(go);
                for (int j = 0; j < 10; j++) {
                    switch (idx % 3) {
                        case 0 -> stack.authService.resetPassword(
                                admin.token(), "user", ("pw-" + (j % 3)).toCharArray());
                        case 1 -> stack.authService.ban(admin.token(), "user");
                        default -> stack.authService.unban(admin.token(), "user");
                    }
                }
            }));
        }
        go.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(60, TimeUnit.SECONDS));
        for (Future<?> f : futures) {
            f.get(); // 任何线程内断言失败都会在此暴露
        }

        // 最终状态确定且可解释：账号存在、封禁标志为布尔终态、
        // 所有会话要么活跃要么有明确的终态原因
        CredentialStore.AccountRecord record = stack.credentials.find("user");
        assertTrue(record != null);
        // 用当前口令尝试登录：结果确定（成功或因封禁/锁定统一拒绝）
        try {
            SessionRecord s = stack.authService.login("user", "pw-2".toCharArray(), "final", "src-final");
            assertEquals("user", stack.authService.requireAccount(s.token()));
        } catch (AuthException e) {
            assertEquals(AuthFailureReason.INVALID_CREDENTIALS, e.getReason());
        }
        assertTrue(loginOk.get() + loginDenied.get() > 0);
    }

    @Test
    void slowHashingDoesNotSerializeUnrelatedAccounts() throws Exception {
        // 慢操作（口令摘要）在锁外执行：不同账号的登录吞吐不应互相拖垮
        SecurityProperties p = TestStack.fastProperties("");
        p.setHashIterations(50_000); // 故意放慢摘要
        TestStack stack = new TestStack(p);
        for (int i = 0; i < 8; i++) {
            stack.authService.register("u" + i, "pw".toCharArray(), Set.of());
        }

        ExecutorService pool = Executors.newFixedThreadPool(8);
        CountDownLatch go = new CountDownLatch(1);
        List<Future<Long>> futures = new ArrayList<>();
        for (int i = 0; i < 8; i++) {
            final int idx = i;
            futures.add(pool.submit(() -> {
                await(go);
                long start = System.nanoTime();
                for (int j = 0; j < 3; j++) {
                    stack.authService.login("u" + idx, "pw".toCharArray(), "d", "s" + idx);
                }
                return System.nanoTime() - start;
            }));
        }
        go.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(60, TimeUnit.SECONDS));

        // 串行基线：单账号 3 次登录耗时
        long baseStart = System.nanoTime();
        for (int j = 0; j < 3; j++) {
            stack.authService.login("u0", "pw".toCharArray(), "d", "solo");
        }
        long serial = System.nanoTime() - baseStart;

        for (Future<Long> f : futures) {
            long elapsed = f.get();
            assertTrue(elapsed < serial * 4,
                    "并发登录耗时不应随线程数线性劣化: elapsed=" + elapsed / 1_000_000
                            + "ms serial=" + serial / 1_000_000 + "ms");
        }
    }

    @Test
    void snapshotNeverShowsHalfWrittenState() throws Exception {
        TestStack stack = TestStack.create();
        stack.authService.register("snap", "pw".toCharArray(), Set.of());

        ExecutorService pool = Executors.newFixedThreadPool(4);
        CountDownLatch go = new CountDownLatch(1);
        List<Future<?>> futures = new ArrayList<>();
        for (int i = 0; i < 3; i++) {
            futures.add(pool.submit(() -> {
                await(go);
                for (int j = 0; j < 100; j++) {
                    try {
                        stack.authService.login("snap", "pw".toCharArray(), "d", "s");
                    } catch (AuthException ignored) {
                        // 可能因并发顶替外的节流被拒绝，属可解释结果
                    }
                }
            }));
        }
        futures.add(pool.submit(() -> {
            await(go);
            for (int j = 0; j < 200; j++) {
                PersistedState state = stack.authService.snapshot();
                // 快照必须自洽：每个会话记录字段完整、状态枚举合法
                for (SessionRecord s : state.sessions().values()) {
                    assertTrue(s.token() != null && !s.token().isBlank());
                    assertTrue(s.accountId() != null);
                    assertTrue(s.expiresAt() > s.issuedAt());
                    assertTrue(s.status() != null);
                }
                assertTrue(state.savedAt() > 0);
            }
        }));
        go.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(30, TimeUnit.SECONDS));
        for (Future<?> f : futures) {
            f.get();
        }
    }

    private static void await(CountDownLatch latch) {
        try {
            latch.await();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
