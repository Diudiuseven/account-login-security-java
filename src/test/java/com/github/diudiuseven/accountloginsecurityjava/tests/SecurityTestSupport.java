package com.github.diudiuseven.accountloginsecurityjava.tests;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.boot.test.web.client.TestRestTemplate;

import java.util.Map;

/** 测试辅助：HTTP 调用与 JSON 取值。 */
final class SecurityTestSupport {

    private SecurityTestSupport() {
    }

    static HttpHeaders jsonHeaders() {
        HttpHeaders h = new HttpHeaders();
        h.set("Content-Type", "application/json");
        return h;
    }

    static HttpHeaders authHeaders(String token) {
        HttpHeaders h = jsonHeaders();
        h.setBearerAuth(token);
        return h;
    }

    static String login(TestRestTemplate rt, String base, String username, String password) {
        return login(rt, base, username, password, null);
    }

    @SuppressWarnings("unchecked")
    static String login(TestRestTemplate rt, String base, String username, String password, String ip) {
        HttpHeaders h = jsonHeaders();
        if (ip != null) {
            h.set("X-Forwarded-For", ip);
        }
        ResponseEntity<Map> resp = rt.postForEntity(base + "/api/auth/login",
                new HttpEntity<>(Map.of("username", username, "password", password), h), Map.class);
        if (!resp.getStatusCode().is2xxSuccessful()) {
            return null;
        }
        return (String) resp.getBody().get("token");
    }

    static ResponseEntity<Map> loginResp(TestRestTemplate rt, String base, String username, String password) {
        return loginResp(rt, base, username, password, null);
    }

    static ResponseEntity<Map> loginResp(TestRestTemplate rt, String base, String username, String password, String ip) {
        HttpHeaders h = jsonHeaders();
        if (ip != null) {
            h.set("X-Forwarded-For", ip);
        }
        return rt.postForEntity(base + "/api/auth/login",
                new HttpEntity<>(Map.of("username", username, "password", password), h), Map.class);
    }

    static void createAccount(TestRestTemplate rt, String base, String adminToken,
                              String username, String password, String role) {
        rt.postForEntity(base + "/api/accounts",
                new HttpEntity<>(Map.of("username", username, "password", password, "role", role),
                        authHeaders(adminToken)), Map.class);
    }

    static ResponseEntity<String> get(TestRestTemplate rt, String base, String path, String token) {
        return rt.exchange(base + path, HttpMethod.GET, new HttpEntity<>(authHeaders(token)), String.class);
    }

    static ResponseEntity<String> post(TestRestTemplate rt, String base, String path, String token) {
        return rt.exchange(base + path, HttpMethod.POST, new HttpEntity<>(authHeaders(token)), String.class);
    }
}
