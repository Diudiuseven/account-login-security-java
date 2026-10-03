package com.github.diudiuseven.accountloginsecurityjava.tests;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.boot.test.web.client.TestRestTemplate;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 封禁/解封测试：
 * 封禁期间登录一律拒绝，已有会话立即失效；
 * 解封后不得沿用封禁前签发的会话。
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "security.password-hash-iterations=1000"
})
class BanUnbanTest {

    @LocalServerPort
    int port;

    @Autowired
    TestRestTemplate rest;

    private String base() {
        return "http://localhost:" + port;
    }

    @Test
    void banBlocksLoginAndRevokesSessions() {
        String admin = SecurityTestSupport.login(rest, base(), "admin", "admin123");
        SecurityTestSupport.createAccount(rest, base(), admin, "banuser", "pw123", "USER");

        String token = SecurityTestSupport.login(rest, base(), "banuser", "pw123");
        assertEquals(200, SecurityTestSupport.get(rest, base(), "/api/sessions", token)
                .getStatusCode().value());

        // 封禁
        assertEquals(200, SecurityTestSupport.post(rest, base(), "/api/accounts/banuser/ban", admin)
                .getStatusCode().value());

        // 封禁期间：正确口令也拒绝
        var loginResp = SecurityTestSupport.loginResp(rest, base(), "banuser", "pw123");
        assertEquals(403, loginResp.getStatusCode().value());
        assertTrue(loginResp.getBody().toString().contains("ACCOUNT_BANNED"));

        // 已有会话立即失效，原因可区分
        var sessionResp = SecurityTestSupport.get(rest, base(), "/api/sessions", token);
        assertEquals(401, sessionResp.getStatusCode().value());
        assertTrue(sessionResp.getBody().contains("SESSION_REVOKED"));
        assertTrue(sessionResp.getBody().contains("BANNED"));
    }

    @Test
    void unbanDoesNotRestoreOldSessions() {
        String admin = SecurityTestSupport.login(rest, base(), "admin", "admin123");
        SecurityTestSupport.createAccount(rest, base(), admin, "unbanuser", "pw123", "USER");

        String oldToken = SecurityTestSupport.login(rest, base(), "unbanuser", "pw123");

        // 封禁后解封
        SecurityTestSupport.post(rest, base(), "/api/accounts/unbanuser/ban", admin);
        SecurityTestSupport.post(rest, base(), "/api/accounts/unbanuser/unban", admin);

        // 解封后：旧会话仍然无效（封禁时已被吊销，不可恢复）
        var oldResp = SecurityTestSupport.get(rest, base(), "/api/sessions", oldToken);
        assertEquals(401, oldResp.getStatusCode().value());
        assertTrue(oldResp.getBody().contains("BANNED"));

        // 解封后可重新登录
        assertEquals(200, SecurityTestSupport.loginResp(rest, base(), "unbanuser", "pw123")
                .getStatusCode().value());
    }
}
