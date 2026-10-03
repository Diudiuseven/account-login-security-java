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

/**
 * 来源 IP 维度并发失败锁定测试：
 * 同一来源并发失败必须收敛到同一锁定结果。
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "security.max-failures=20",
        "security.lock-duration-ms=2000",
        "security.ip-max-failures=2",
        "security.password-hash-iterations=1000"
})
class IpLockoutTest {

    @LocalServerPort
    int port;

    @Autowired
    TestRestTemplate rest;

    private String base() {
        return "http://localhost:" + port;
    }

    @Test
    void ipLevelThrottlingConverges() throws Exception {
        String admin = SecurityTestSupport.login(rest, base(), "admin", "admin123");
        for (int i = 0; i < 5; i++) {
            SecurityTestSupport.createAccount(rest, base(), admin, "ipu" + i, "pw123", "USER");
        }
        String ip = "10.2.0.1";
        int threads = 8;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<Integer>> futures = new ArrayList<>();
        for (int i = 0; i < threads; i++) {
            final int idx = i;
            futures.add(pool.submit(() -> {
                start.await();
                return SecurityTestSupport.loginResp(rest, base(), "ipu" + (idx % 5), "wrongpw", ip)
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
        // IP 阈值 2：同一来源恰好 2 次放行，其余全部锁定
        assertEquals(2, bad, "IP 维度 BAD_CREDENTIALS 必须恰好 2 次");
        assertEquals(threads - 2, locked);
    }
}
