package com.github.diudiuseven.accountloginsecurityjava.tests;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.boot.test.web.client.TestRestTemplate;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * MULTI 策略测试：多端登录并存，互不影响。
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "security.session-strategy=MULTI",
        "security.password-hash-iterations=1000"
})
class MultiSessionTest {

    @LocalServerPort
    int port;

    @Autowired
    TestRestTemplate rest;

    private String base() {
        return "http://localhost:" + port;
    }

    @Test
    void multipleSessionsCoexist() {
        String admin = SecurityTestSupport.login(rest, base(), "admin", "admin123");
        SecurityTestSupport.createAccount(rest, base(), admin, "multiuser", "pw123", "USER");

        String t1 = SecurityTestSupport.login(rest, base(), "multiuser", "pw123");
        String t2 = SecurityTestSupport.login(rest, base(), "multiuser", "pw123");

        // 两端会话并存
        assertEquals(200, SecurityTestSupport.get(rest, base(), "/api/sessions", t1)
                .getStatusCode().value());
        assertEquals(200, SecurityTestSupport.get(rest, base(), "/api/sessions", t2)
                .getStatusCode().value());
    }
}
