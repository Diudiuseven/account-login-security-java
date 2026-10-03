package com.github.diudiuseven.accountloginsecurityjava.tests;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.boot.test.web.client.TestRestTemplate;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 高并发测试：登录与封禁同时发生。
 * 任意请求不得读到写了一半的中间状态（无 500）；
 * 封禁完成后所有登录请求必须被拒绝，结果确定。
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "security.password-hash-iterations=1000"
})
class ConcurrentBanAndLoginTest {

    @LocalServerPort
    int port;

    @Autowired
    TestRestTemplate rest;

    private String base() {
        return "http://localhost:" + port;
    }

    @Test
    void concurrentLoginsAndBanProduceDeterministicResult() throws Exception {
        String admin = SecurityTestSupport.login(rest, base(), "admin", "admin123");
        SecurityTestSupport.createAccount(rest, base(), admin, "concurrentuser", "pw123", "USER");

        int loginThreads = 20;
        ExecutorService pool = Executors.newFixedThreadPool(loginThreads + 1);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<Integer>> futures = new ArrayList<>();
        // 20 个并发登录
        for (int i = 0; i < loginThreads; i++) {
            futures.add(pool.submit(() -> {
                start.await();
                return SecurityTestSupport.loginResp(rest, base(), "concurrentuser", "pw123")
                        .getStatusCode().value();
            }));
        }
        // 1 个并发封禁
        futures.add(pool.submit(() -> {
            start.await();
            return SecurityTestSupport.post(rest, base(), "/api/accounts/concurrentuser/ban", admin)
                    .getStatusCode().value();
        }));
        start.countDown();

        List<Integer> codes = new ArrayList<>();
        for (Future<Integer> f : futures) {
            codes.add(f.get());
        }
        pool.shutdownNow();

        // 不得有 500（无半写状态/内部错误）
        long serverErrors = codes.stream().filter(c -> c >= 500).count();
        assertEquals(0, serverErrors, "并发下不得出现 5xx 内部错误");

        // 封禁完成后：所有登录请求必须被拒绝（403）
        for (int i = 0; i < 5; i++) {
            int code = SecurityTestSupport.loginResp(rest, base(), "concurrentuser", "pw123")
                    .getStatusCode().value();
            assertEquals(403, code, "封禁后登录必须被拒绝");
        }
    }

    @Test
    void loginsAfterBanAllRejected() {
        String admin = SecurityTestSupport.login(rest, base(), "admin", "admin123");
        SecurityTestSupport.createAccount(rest, base(), admin, "banafteruser", "pw123", "USER");

        // 先封禁
        SecurityTestSupport.post(rest, base(), "/api/accounts/banafteruser/ban", admin);

        // 并发登录：全部 403，无 500
        int threads = 10;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<Integer>> futures = new ArrayList<>();
        for (int i = 0; i < threads; i++) {
            futures.add(pool.submit(() -> {
                try {
                    start.await();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
                return SecurityTestSupport.loginResp(rest, base(), "banafteruser", "pw123")
                        .getStatusCode().value();
            }));
        }
        start.countDown();
        List<Integer> codes = new ArrayList<>();
        for (Future<Integer> f : futures) {
            try {
                codes.add(f.get());
            } catch (Exception e) {
                codes.add(500);
            }
        }
        pool.shutdownNow();

        long rejected = codes.stream().filter(c -> c == 403).count();
        long serverErrors = codes.stream().filter(c -> c >= 500).count();
        assertEquals(threads, rejected, "封禁后所有登录必须被拒绝");
        assertEquals(0, serverErrors, "不得出现 5xx");
    }
}
