package com.github.diudiuseven.accountloginsecurityjava.tests;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.diudiuseven.accountloginsecurityjava.Application;
import org.junit.jupiter.api.Test;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.core.env.MapPropertySource;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 重启恢复测试：
 * 已注销会话不得复活；锁定不得超过既定到期时间；
 * 重启期间未完成的登录状态必须可区分（INTERRUPTED）。
 */
class RestartRecoveryTest {

    private static final Path DIR = Path.of("/tmp/sec-restart-test");
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static void deleteDir(Path dir) {
        try {
            if (Files.exists(dir)) {
                try (var walk = Files.walk(dir)) {
                    walk.sorted(Comparator.reverseOrder()).forEach(p -> {
                        try { Files.deleteIfExists(p); } catch (Exception ignored) {}
                    });
                }
            }
        } catch (Exception ignored) {}
    }

    private SpringApplicationBuilder builder(String storeDir) {
        return new SpringApplicationBuilder(Application.class)
                .web(WebApplicationType.SERVLET)
                .bannerMode(org.springframework.boot.Banner.Mode.OFF)
                .initializers(ctx -> {
                    Map<String, Object> props = new HashMap<>();
                    props.put("server.port", "0");
                    props.put("security.store-dir", storeDir);
                    props.put("security.password-hash-iterations", "1000");
                    props.put("security.max-failures", "3");
                    props.put("security.lock-duration-ms", "60000");
                    props.put("security.ip-max-failures", "20");
                    props.put("security.session-strategy", "KICK_OUT");
                    ctx.getEnvironment().getPropertySources()
                            .addFirst(new MapPropertySource("restartTestProps", props));
                });
    }

    @Test
    void revokedSessionsStayRevokedAndLockPersists() throws Exception {
        String storeDir = DIR.resolve("data").toString();
        deleteDir(DIR);

        String t1;
        String t2;
        // 第一个进程生命周期
        try (ConfigurableApplicationContext ctx = builder(storeDir).run()) {
            String base = "http://localhost:" + ctx.getEnvironment()
                    .getProperty("local.server.port", Integer.class);
            TestRestTemplate rt = new TestRestTemplate();

            String admin = SecurityTestSupport.login(rt, base, "admin", "admin123");
            SecurityTestSupport.createAccount(rt, base, admin, "restartuser", "pw123", "USER");
            t1 = SecurityTestSupport.login(rt, base, "restartuser", "pw123");
            SecurityTestSupport.post(rt, base, "/api/auth/logout", t1);
            t2 = SecurityTestSupport.login(rt, base, "restartuser", "pw123");

            // 触发账号锁定（4 次失败）
            for (int i = 0; i < 4; i++) {
                SecurityTestSupport.loginResp(rt, base, "restartuser", "wrongpw");
            }
            assertEquals(423, SecurityTestSupport.loginResp(rt, base, "restartuser", "pw123")
                    .getStatusCode().value(), "重启前应已锁定");
        }

        // 第二个进程生命周期（重启）
        try (ConfigurableApplicationContext ctx = builder(storeDir).run()) {
            String base = "http://localhost:" + ctx.getEnvironment()
                    .getProperty("local.server.port", Integer.class);
            TestRestTemplate rt = new TestRestTemplate();

            // 已注销会话不得复活
            var r1 = SecurityTestSupport.get(rt, base, "/api/sessions", t1);
            assertEquals(401, r1.getStatusCode().value());
            assertTrue(r1.getBody().contains("SESSION_REVOKED"));
            assertTrue(r1.getBody().contains("LOGOUT"));

            // 未注销会话恢复后仍有效
            assertEquals(200, SecurityTestSupport.get(rt, base, "/api/sessions", t2)
                    .getStatusCode().value());

            // 锁定保持（未到期），正确口令也拒绝
            assertEquals(423, SecurityTestSupport.loginResp(rt, base, "restartuser", "pw123")
                    .getStatusCode().value());
        }
    }

    @Test
    void interruptedLoginBecomesDistinguishableOnRestart() throws Exception {
        String storeDir = DIR.resolve("data").toString();
        deleteDir(DIR);

        // 第一个进程：正常启动后停止
        try (ConfigurableApplicationContext ctx = builder(storeDir).run()) {
            // 进程正常退出
        }

        // 进程停止后，写入 PENDING 登录尝试 + 对应 ACTIVE 会话（模拟重启瞬间未完成的登录）
        Path dir = Path.of(storeDir);
        String token = "interrupted-token-123";
        Map<String, Object> attempt = new HashMap<>();
        attempt.put("attemptId", "attempt-1");
        attempt.put("username", "interrupteduser");
        attempt.put("ip", "127.0.0.1");
        attempt.put("startedAt", System.currentTimeMillis());
        attempt.put("status", "PENDING");
        attempt.put("reason", null);
        attempt.put("sessionToken", token);
        Map<String, Object> attempts = new HashMap<>();
        attempts.put("attempt-1", attempt);
        MAPPER.writeValue(dir.resolve("login-attempts.json").toFile(), attempts);

        long now = System.currentTimeMillis();
        Map<String, Object> session = new HashMap<>();
        session.put("token", token);
        session.put("username", "interrupteduser");
        session.put("issuedAt", now);
        session.put("expiresAt", now + 1_800_000);
        session.put("status", "ACTIVE");
        session.put("device", "pc");
        session.put("ip", "127.0.0.1");
        session.put("revokeReason", null);
        Map<String, Object> sessions = new HashMap<>();
        sessions.put(token, session);
        MAPPER.writeValue(dir.resolve("sessions.json").toFile(), sessions);

        // 重启
        try (ConfigurableApplicationContext ctx = builder(storeDir).run()) {
            String base = "http://localhost:" + ctx.getEnvironment()
                    .getProperty("local.server.port", Integer.class);
            TestRestTemplate rt = new TestRestTemplate();

            // 未完成登录必须变为 INTERRUPTED（可区分）
            Map<String, Object> loadedAttempts = MAPPER.readValue(
                    Files.readString(dir.resolve("login-attempts.json")),
                    new TypeReference<>() {});
            @SuppressWarnings("unchecked")
            Map<String, Object> a = (Map<String, Object>) loadedAttempts.get("attempt-1");
            assertEquals("INTERRUPTED", a.get("status"));

            // 其会话必须被吊销，原因可区分
            Map<String, Object> loadedSessions = MAPPER.readValue(
                    Files.readString(dir.resolve("sessions.json")),
                    new TypeReference<>() {});
            @SuppressWarnings("unchecked")
            Map<String, Object> s = (Map<String, Object>) loadedSessions.get(token);
            assertEquals("REVOKED", s.get("status"));
            assertEquals("INTERRUPTED_BY_RESTART", s.get("revokeReason"));

            // 使用该会话必须被拒
            var resp = SecurityTestSupport.get(rt, base, "/api/sessions", token);
            assertEquals(401, resp.getStatusCode().value());
            assertTrue(resp.getBody().contains("INTERRUPTED_BY_RESTART"));
        }
    }
}
