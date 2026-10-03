package com.github.diudiuseven.accountloginsecurityjava.tests;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 会话策略测试：KICK_OUT 下新登录顶替旧会话；改密/注销立即失效。
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "security.session-strategy=KICK_OUT",
        "security.password-hash-iterations=1000"
})
class SessionStrategyTest {

    @LocalServerPort
    int port;

    @Autowired
    TestRestTemplate rest;

    private String base() {
        return "http://localhost:" + port;
    }

    @Test
    void newLoginKicksOutOldSessions() {
        String admin = SecurityTestSupport.login(rest, base(), "admin", "admin123");
        SecurityTestSupport.createAccount(rest, base(), admin, "kickuser", "pw123", "USER");

        String t1 = SecurityTestSupport.login(rest, base(), "kickuser", "pw123");
        String t2 = SecurityTestSupport.login(rest, base(), "kickuser", "pw123");

        // 旧会话被顶替：立即失效，原因可区分
        ResponseEntity<String> oldResp = SecurityTestSupport.get(rest, base(), "/api/sessions", t1);
        assertEquals(401, oldResp.getStatusCode().value());
        assertTrue(oldResp.getBody().contains("SESSION_REVOKED"), "应给出被吊销原因");
        assertTrue(oldResp.getBody().contains("KICK_OUT"), "应区分被顶替原因");

        // 新会话正常
        assertEquals(200, SecurityTestSupport.get(rest, base(), "/api/sessions", t2)
                .getStatusCode().value());
    }

    @Test
    void logoutRevokesImmediately() {
        String admin = SecurityTestSupport.login(rest, base(), "admin", "admin123");
        SecurityTestSupport.createAccount(rest, base(), admin, "logoutuser", "pw123", "USER");

        String token = SecurityTestSupport.login(rest, base(), "logoutuser", "pw123");
        assertEquals(200, SecurityTestSupport.post(rest, base(), "/api/auth/logout", token)
                .getStatusCode().value());
        ResponseEntity<String> resp = SecurityTestSupport.get(rest, base(), "/api/sessions", token);
        assertEquals(401, resp.getStatusCode().value());
        assertTrue(resp.getBody().contains("SESSION_REVOKED"));
        assertTrue(resp.getBody().contains("LOGOUT"));
    }

    @Test
    void passwordChangeRevokesSessions() {
        String admin = SecurityTestSupport.login(rest, base(), "admin", "admin123");
        SecurityTestSupport.createAccount(rest, base(), admin, "pwchangeuser", "oldpw", "USER");

        String token = SecurityTestSupport.login(rest, base(), "pwchangeuser", "oldpw");
        // 本人改密
        HttpEntity<Map<String, String>> entity = new HttpEntity<>(
                Map.of("oldPassword", "oldpw", "newPassword", "newpw"),
                SecurityTestSupport.authHeaders(token));
        ResponseEntity<String> changeResp = rest.exchange(base() + "/api/accounts/me/password",
                HttpMethod.POST, entity, String.class);
        assertEquals(200, changeResp.getStatusCode().value());

        // 改密后旧会话立即失效，原因可区分
        ResponseEntity<String> resp = SecurityTestSupport.get(rest, base(), "/api/sessions", token);
        assertEquals(401, resp.getStatusCode().value());
        assertTrue(resp.getBody().contains("CREDENTIAL_CHANGED"), "应区分凭据变更原因");

        // 旧口令登录失败，新口令可登录
        assertEquals(401, SecurityTestSupport.loginResp(rest, base(), "pwchangeuser", "oldpw")
                .getStatusCode().value());
        assertEquals(200, SecurityTestSupport.loginResp(rest, base(), "pwchangeuser", "newpw")
                .getStatusCode().value());
    }
}
