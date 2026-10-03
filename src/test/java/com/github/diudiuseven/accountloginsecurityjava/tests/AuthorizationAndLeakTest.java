package com.github.diudiuseven.accountloginsecurityjava.tests;

import com.github.diudiuseven.accountloginsecurityjava.config.SecurityProperties;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.boot.test.web.client.TestRestTemplate;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 越权与信息泄露测试：
 * 不存在账号与错误口令返回相同错误且耗时一致；
 * 越权请求被拒绝并写入审计，可追溯。
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "security.password-hash-iterations=1000"
})
class AuthorizationAndLeakTest {

    @LocalServerPort
    int port;

    @Autowired
    TestRestTemplate rest;

    @Autowired
    SecurityProperties properties;

    private String base() {
        return "http://localhost:" + port;
    }

    @Test
    void nonexistentAndWrongPasswordHaveSameResponseAndTiming() {
        String admin = SecurityTestSupport.login(rest, base(), "admin", "admin123");
        SecurityTestSupport.createAccount(rest, base(), admin, "realuser", "pw123", "USER");

        // 错误内容一致
        var ghost = SecurityTestSupport.loginResp(rest, base(), "ghost-no-such-user", "whatever");
        var wrong = SecurityTestSupport.loginResp(rest, base(), "realuser", "wrongpw");
        assertEquals(401, ghost.getStatusCode().value());
        assertEquals(401, wrong.getStatusCode().value());
        assertEquals(ghost.getBody().get("code"), wrong.getBody().get("code"));
        assertEquals(ghost.getBody().get("message"), wrong.getBody().get("message"));

        // 耗时一致：两者都执行一次 PBKDF2，中位数耗时相差不超过 5 倍
        long ghostMedian = medianTime("ghost-no-such-user", "whatever");
        long wrongMedian = medianTime("realuser", "wrongpw");
        long ratio = Math.max(ghostMedian, wrongMedian) / Math.max(1, Math.min(ghostMedian, wrongMedian));
        assertTrue(ratio <= 5, "响应耗时不得泄露账号存在性: ghost=" + ghostMedian
                + "ms, wrong=" + wrongMedian + "ms, ratio=" + ratio);
    }

    @Test
    void privilegeEscalationIsDeniedAndAudited() throws Exception {
        String admin = SecurityTestSupport.login(rest, base(), "admin", "admin123");
        SecurityTestSupport.createAccount(rest, base(), admin, "plainuser", "pw123", "USER");
        String userToken = SecurityTestSupport.login(rest, base(), "plainuser", "pw123");

        // 普通用户尝试开户（管理员操作）→ 403
        org.springframework.http.HttpHeaders h = SecurityTestSupport.authHeaders(userToken);
        var r1 = rest.postForEntity(base() + "/api/accounts",
                new org.springframework.http.HttpEntity<>(java.util.Map.of("username", "x", "password", "y"), h),
                String.class);
        assertEquals(403, r1.getStatusCode().value());
        assertTrue(r1.getBody().contains("FORBIDDEN"));

        // 普通用户尝试封禁他人 → 403
        var r2 = SecurityTestSupport.post(rest, base(), "/api/accounts/admin/ban", userToken);
        Files.writeString(Path.of(properties.getStoreDir(), "r2.txt"),
                r2.getStatusCode() + " " + r2.getBody());
        assertEquals(403, r2.getStatusCode().value());

        // 普通用户尝试查看他人会话 → 403
        var r3 = SecurityTestSupport.get(rest, base(), "/api/sessions?username=admin", userToken);
        assertEquals(403, r3.getStatusCode().value());

        // 审计可追溯
        Path audit = Path.of(properties.getStoreDir(), "audit.log");
        assertTrue(Files.exists(audit), "审计日志必须落盘");
        List<String> lines = Files.readAllLines(audit);
        long denied = lines.stream()
                .filter(l -> l.contains("UNAUTHORIZED_ACCESS"))
                .filter(l -> l.contains("DENIED"))
                .count();
        assertTrue(denied >= 3, "越权请求必须被审计记录，实际 DENIED 记录数=" + denied);
    }

    private long medianTime(String username, String password) {
        List<Long> times = new ArrayList<>();
        for (int i = 0; i < 5; i++) {
            long t0 = System.nanoTime();
            SecurityTestSupport.loginResp(rest, base(), username, password);
            times.add((System.nanoTime() - t0) / 1_000_000);
        }
        times.sort(Long::compare);
        return times.get(times.size() / 2);
    }
}
