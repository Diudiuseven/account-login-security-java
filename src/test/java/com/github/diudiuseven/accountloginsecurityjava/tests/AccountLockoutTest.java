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
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * 账号维度并发失败锁定测试：
 * 同一账号并发失败必须收敛到同一锁定结果，不得多放行；
 * 锁定到期后自动恢复并清空计数。
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "security.max-failures=3",
        "security.lock-duration-ms=2000",
        "security.ip-max-failures=20",
        "security.password-hash-iterations=1000"
})
class AccountLockoutTest {

    @LocalServerPort
    int port;

    @Autowired
    TestRestTemplate rest;

    private String base() {
        return "http://localhost:" + port;
    }

    @Test
    void concurrentFailuresConvergeToSingleLockResult() throws Exception {
        String admin = SecurityTestSupport.login(rest, base(), "admin", "admin123");
        SecurityTestSupport.createAccount(rest, base(), admin, "lockuser", "pw123", "USER");

        int threads = 12;
        String ip = "10.1.0.1";
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<Integer>> futures = new ArrayList<>();
        for (int i = 0; i < threads; i++) {
            futures.add(pool.submit(() -> {
                start.await();
                return SecurityTestSupport.loginResp(rest, base(), "lockuser", "wrongpw", ip)
                        .getStatusCode().value();
            }));
        }
        start.countDown();

        List<Integer> codes = new ArrayList<>();
        for (Future<Integer> f : futures) {
            codes.add(f.get());
        }
        pool.shutdownNow();

        long bad = codes.stream().filter(c -> c == 401).count();
        long locked = codes.stream().filter(c -> c == 423).count();
        // 账号阈值 3：恰好 3 次 BAD_CREDENTIALS，其余全部 ACCOUNT_LOCKED，竞态下也不多放行
        assertEquals(3, bad, "BAD_CREDENTIALS 次数必须恰好等于阈值");
        assertEquals(threads - 3, locked, "其余请求必须全部被锁定");
    }

    @Test
    void lockExpiryAutoResetsCounter() throws Exception {
        String admin = SecurityTestSupport.login(rest, base(), "admin", "admin123");
        SecurityTestSupport.createAccount(rest, base(), admin, "expireuser", "pw123", "USER");

        String ip = "10.1.0.2";
        // 阈值 3：连续 4 次失败触发锁定（前 3 次放行，第 4 次起锁定）
        for (int i = 0; i < 4; i++) {
            SecurityTestSupport.loginResp(rest, base(), "expireuser", "wrongpw", ip);
        }
        assertEquals(423, SecurityTestSupport.loginResp(rest, base(), "expireuser", "pw123", ip)
                .getStatusCode().value(), "锁定期内正确口令也必须被拒");

        Thread.sleep(2300);

        String token = SecurityTestSupport.login(rest, base(), "expireuser", "pw123", ip);
        assertNotNull(token, "锁定到期后应自动恢复登录");

        // 账号计数已清空：再次失败从 1 开始，不会立即锁定
        assertEquals(401, SecurityTestSupport.loginResp(rest, base(), "expireuser", "wrongpw", ip)
                .getStatusCode().value());
        assertEquals(401, SecurityTestSupport.loginResp(rest, base(), "expireuser", "wrongpw", ip)
                .getStatusCode().value());
    }
}
