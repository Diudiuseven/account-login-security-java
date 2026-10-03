package com.github.diudiuseven.accountloginsecurityjava.security.api;

import java.util.List;
import java.util.Map;

import com.github.diudiuseven.accountloginsecurityjava.security.AuditLog;
import com.github.diudiuseven.accountloginsecurityjava.security.AuthService;
import com.github.diudiuseven.accountloginsecurityjava.security.SessionRecord;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 登录/会话 REST 入口。
 * 口令只在内存中以 char[] 短暂存在并立即清空；请求体绝不进日志；
 * 登录失败响应对外统一，不泄露账号存在性。
 */
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private static final String TOKEN_HEADER = "X-Session-Token";

    private final AuthService authService;
    private final AuditLog auditLog;

    public AuthController(AuthService authService, AuditLog auditLog) {
        this.authService = authService;
        this.auditLog = auditLog;
    }

    /** 口令字段绝不出现在 toString/日志中。 */
    public record LoginRequest(String accountId, String password, String deviceId) {
        @Override
        public String toString() {
            return "LoginRequest[accountId=" + accountId + ", password=***, deviceId=" + deviceId + "]";
        }
    }

    public record ChangePasswordRequest(String oldPassword, String newPassword) {
        @Override
        public String toString() {
            return "ChangePasswordRequest[oldPassword=***, newPassword=***]";
        }
    }

    public record ResetPasswordRequest(String targetAccount, String newPassword) {
        @Override
        public String toString() {
            return "ResetPasswordRequest[targetAccount=" + targetAccount + ", newPassword=***]";
        }
    }

    public record TargetRequest(String targetAccount) {
    }

    public record SessionResponse(String token, String accountId, long expiresAt) {
    }

    @PostMapping("/login")
    public SessionResponse login(@RequestBody LoginRequest request, HttpServletRequest http) {
        char[] password = request.password() != null ? request.password().toCharArray() : new char[0];
        try {
            SessionRecord session = authService.login(
                    request.accountId(), password,
                    request.deviceId() != null ? request.deviceId() : "default",
                    source(http));
            return new SessionResponse(session.token(), session.accountId(), session.expiresAt());
        } finally {
            java.util.Arrays.fill(password, '\0');
        }
    }

    @PostMapping("/logout")
    public Map<String, String> logout(@RequestHeader(TOKEN_HEADER) String token) {
        authService.logout(token);
        return Map.of("status", "ok");
    }

    @PostMapping("/renew")
    public SessionResponse renew(@RequestHeader(TOKEN_HEADER) String token) {
        SessionRecord session = authService.renew(token);
        return new SessionResponse(session.token(), session.accountId(), session.expiresAt());
    }

    @GetMapping("/whoami")
    public Map<String, String> whoami(@RequestHeader(TOKEN_HEADER) String token) {
        return Map.of("accountId", authService.requireAccount(token));
    }

    @PostMapping("/password/change")
    public Map<String, String> changePassword(@RequestHeader(TOKEN_HEADER) String token,
                                              @RequestBody ChangePasswordRequest request) {
        char[] oldPassword = request.oldPassword() != null ? request.oldPassword().toCharArray() : new char[0];
        char[] newPassword = request.newPassword() != null ? request.newPassword().toCharArray() : new char[0];
        try {
            authService.changePassword(token, oldPassword, newPassword);
            return Map.of("status", "ok");
        } finally {
            java.util.Arrays.fill(oldPassword, '\0');
            java.util.Arrays.fill(newPassword, '\0');
        }
    }

    @PostMapping("/password/reset")
    public Map<String, String> resetPassword(@RequestHeader(TOKEN_HEADER) String token,
                                             @RequestBody ResetPasswordRequest request) {
        char[] newPassword = request.newPassword() != null ? request.newPassword().toCharArray() : new char[0];
        try {
            authService.resetPassword(token, request.targetAccount(), newPassword);
            return Map.of("status", "ok");
        } finally {
            java.util.Arrays.fill(newPassword, '\0');
        }
    }

    @PostMapping("/ban")
    public Map<String, String> ban(@RequestHeader(TOKEN_HEADER) String token,
                                   @RequestBody TargetRequest request) {
        authService.ban(token, request.targetAccount());
        return Map.of("status", "ok");
    }

    @PostMapping("/unban")
    public Map<String, String> unban(@RequestHeader(TOKEN_HEADER) String token,
                                     @RequestBody TargetRequest request) {
        authService.unban(token, request.targetAccount());
        return Map.of("status", "ok");
    }

    /** 审计查询（需管理员会话），用于越权与敏感操作追溯。 */
    @GetMapping("/audit")
    public List<AuditLog.Event> audit(@RequestHeader(TOKEN_HEADER) String token) {
        authService.requireAdminAccount(token, "audit-read");
        return auditLog.events();
    }

    private String source(HttpServletRequest http) {
        String forwarded = http.getHeader("X-Forwarded-For");
        return forwarded != null ? forwarded : http.getRemoteAddr();
    }
}
