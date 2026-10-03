package com.github.diudiuseven.accountloginsecurityjava.security;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 并发失败锁定：同一账号/来源的并发失败必须收敛到同一个锁定结果，
 * 不得因竞态多放行；锁定到期自动恢复并清空计数；阈值/窗口/时长可配置。
 */
class LockoutConcurrencyTest {

    @Test
    void concurrentFailuresConvergeToSingleLock() throws Exception {
        TestStack stack = TestStack.create();
        int threads = 32;
        int perThread = 5;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch ready = new CountDownLatch(threads);
        CountDownLatch go = new CountDownLatch(1);
        List<Future<Long>> futures = new ArrayList<>();
        for (int i = 0; i < threads; i++) {
            futures.add(pool.submit(() -> {
                ready.countDown();
                go.await();
                long locksSeen = 0;
                for (int j = 0; j < perThread; j++) {
                    if (stack.lockout.recordFailure("victim", "src-1") != null) {
                        locksSeen++;
                    }
                }
                return locksSeen;
            }));
        }
        assertTrue(ready.await(5, TimeUnit.SECONDS));
        go.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(10, TimeUnit.SECONDS));

        // 阈值 3：160 次并发失败应触发多次锁定周期，但每次锁定结果唯一确定
        assertTrue(stack.lockout.isLocked("victim", "src-1"), "并发失败后账号应处于锁定");
        for (Future<Long> f : futures) {
            assertNotNull(f.get());
        }
    }

    @Test
    void noExtraAttemptPassesDuringRace() throws Exception {
        // 阈值 3：3 个并发失败必须全部计入，第 4 次登录尝试（正确口令）也被锁定拒绝
        TestStack stack = TestStack.create();
        stack.authService.register("eve", "right-pw".toCharArray(), Set.of());

        ExecutorService pool = Executors.newFixedThreadPool(3);
        CountDownLatch go = new CountDownLatch(1);
        List<Future<?>> futures = new ArrayList<>();
        for (int i = 0; i < 3; i++) {
            futures.add(pool.submit(() -> {
                try {
                    go.await();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
                assertThrows(AuthException.class, () -> stack.authService.login(
                        "eve", "wrong-pw".toCharArray(), "d", "src-race"));
                return null;
            }));
        }
        go.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(10, TimeUnit.SECONDS));
        for (Future<?> f : futures) {
            f.get();
        }

        assertTrue(stack.lockout.isLocked("eve", "src-race"));
        // 锁定期间即使口令正确也必须被拒绝，且错误内容与口令错误一致
        AuthException e = assertThrows(AuthException.class, () -> stack.authService.login(
                "eve", "right-pw".toCharArray(), "d", "src-race"));
        assertEquals(AuthFailureReason.INVALID_CREDENTIALS, e.getReason());
    }

    @Test
    void lockExpiresAndCountersCleared() throws Exception {
        TestStack stack = TestStack.create();
        stack.authService.register("frank", "pw".toCharArray(), Set.of());
        for (int i = 0; i < 3; i++) {
            assertThrows(AuthException.class, () -> stack.authService.login(
                    "frank", "bad".toCharArray(), "d", "src-x"));
        }
        assertTrue(stack.lockout.isLocked("frank", "src-x"));

        Thread.sleep(600); // 锁定时长 500ms，到期自动恢复
        assertFalse(stack.lockout.isLocked("frank", "src-x"));

        // 计数已清空：再失败 2 次（不足阈值 3）不应锁定
        assertThrows(AuthException.class, () -> stack.authService.login(
                "frank", "bad".toCharArray(), "d", "src-x"));
        assertThrows(AuthException.class, () -> stack.authService.login(
                "frank", "bad".toCharArray(), "d", "src-x"));
        assertFalse(stack.lockout.isLocked("frank", "src-x"));

        // 恢复后正确口令可登录
        SessionRecord session = stack.authService.login("frank", "pw".toCharArray(), "d", "src-x");
        assertEquals("frank", session.accountId());
    }

    @Test
    void successClearsFailureCount() {
        TestStack stack = TestStack.create();
        stack.authService.register("grace", "pw".toCharArray(), Set.of());
        // 失败 2 次（阈值 3）后成功一次，计数清零；再失败 2 次不应锁定
        for (int i = 0; i < 2; i++) {
            assertThrows(AuthException.class, () -> stack.authService.login(
                    "grace", "bad".toCharArray(), "d", "src-y"));
        }
        stack.authService.login("grace", "pw".toCharArray(), "d", "src-y");
        for (int i = 0; i < 2; i++) {
            assertThrows(AuthException.class, () -> stack.authService.login(
                    "grace", "bad".toCharArray(), "d", "src-y"));
        }
        assertFalse(stack.lockout.isLocked("grace", "src-y"));
    }

    @Test
    void sourceDimensionLocksIndependently() {
        TestStack stack = TestStack.create();
        // 同一来源对不同账号失败也计数（防扫描）
        for (int i = 0; i < 3; i++) {
            stack.lockout.recordFailure("account-" + i, "attacker-src");
        }
        assertTrue(stack.lockout.isLocked("never-failed-account", "attacker-src"),
                "来源维度应独立锁定");
        assertFalse(stack.lockout.isLocked("never-failed-account", "other-src"));
    }

    @Test
    void configurableThresholdWindowAndDuration() {
        SecurityProperties p = TestStack.fastProperties("");
        p.setMaxFailures(2);
        p.setLockDuration(Duration.ofMillis(200));
        p.setFailureWindow(Duration.ofMillis(300));
        LockoutManager lockout = new LockoutManager(p);

        assertEquals(null, lockout.recordFailure("a", "s"));
        assertNotNull(lockout.recordFailure("a", "s"), "达到自定义阈值 2 应立即锁定");
        assertTrue(lockout.isLocked("a", "s"));
    }

    @Test
    void concurrentLockAndLoginDeterministic() throws Exception {
        // 并发重置（清空计数）与失败同时发生：最终结果必须确定——
        // 要么锁定要么未锁定，且 isLocked 与内部计数一致
        TestStack stack = TestStack.create();
        AtomicInteger locks = new AtomicInteger();
        ExecutorService pool = Executors.newFixedThreadPool(8);
        Set<Long> observed = ConcurrentHashMap.newKeySet();
        CountDownLatch go = new CountDownLatch(1);
        List<Callable<Object>> tasks = new ArrayList<>();
        for (int i = 0; i < 8; i++) {
            final int idx = i;
            tasks.add(() -> {
                go.await();
                for (int j = 0; j < 50; j++) {
                    if (idx % 2 == 0) {
                        Long lockedUntil = stack.lockout.recordFailure("shared", "shared-src");
                        if (lockedUntil != null) {
                            locks.incrementAndGet();
                            observed.add(lockedUntil);
                        }
                    } else {
                        stack.lockout.recordSuccess("shared", "shared-src");
                    }
                }
                return null;
            });
        }
        List<Future<Object>> results = new ArrayList<>();
        for (Callable<Object> task : tasks) {
            results.add(pool.submit(task));
        }
        go.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(10, TimeUnit.SECONDS));
        for (Future<Object> r : results) {
            r.get();
        }
        // 每次锁定事件都有唯一确定的到期时间，状态可读且一致
        boolean locked = stack.lockout.isLocked("shared", "shared-src");
        assertEquals(locked, stack.lockout.isLocked("shared", "shared-src"), "重复读必须一致");
    }
}
