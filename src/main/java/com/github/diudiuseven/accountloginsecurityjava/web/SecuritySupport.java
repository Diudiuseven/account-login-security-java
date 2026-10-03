package com.github.diudiuseven.accountloginsecurityjava.web;

import com.github.diudiuseven.accountloginsecurityjava.model.Role;
import com.github.diudiuseven.accountloginsecurityjava.model.Session;
import com.github.diudiuseven.accountloginsecurityjava.service.AuditService;
import jakarta.servlet.http.HttpServletRequest;

/** 控制器侧的鉴权辅助：取当前会话、判定角色、越权审计。 */
public final class SecuritySupport {

    public static final String ATTR_SESSION = "currentSession";
    public static final String ATTR_USERNAME = "currentUsername";
    public static final String ATTR_ROLE = "currentRole";

    private SecuritySupport() {
    }

    public static Session currentSession(HttpServletRequest request) {
        return (Session) request.getAttribute(ATTR_SESSION);
    }

    public static String currentUsername(HttpServletRequest request) {
        return (String) request.getAttribute(ATTR_USERNAME);
    }

    public static Role currentRole(HttpServletRequest request) {
        return (Role) request.getAttribute(ATTR_ROLE);
    }

    public static boolean isAdmin(HttpServletRequest request) {
        return currentRole(request) == Role.ADMIN;
    }

    /** 要求管理员；否则抛 FORBIDDEN 并记录越权审计。 */
    public static void requireAdmin(HttpServletRequest request, AuditService auditService, String action) {
        if (!isAdmin(request)) {
            String username = currentUsername(request);
            auditService.log(AuditService.UNAUTHORIZED_ACCESS, username,
                    clientIp(request), "action=" + action + ", requiredRole=ADMIN", "DENIED");
            throw new SecurityApiException(ErrorCode.FORBIDDEN, "无权执行该操作");
        }
    }

    /** 要求本人或管理员；否则抛 FORBIDDEN 并记录越权审计。 */
    public static void requireSelfOrAdmin(HttpServletRequest request, AuditService auditService,
                                          String targetUsername, String action) {
        String username = currentUsername(request);
        if (targetUsername != null && targetUsername.equals(username)) {
            return;
        }
        if (isAdmin(request)) {
            return;
        }
        auditService.log(AuditService.UNAUTHORIZED_ACCESS, username,
                clientIp(request), "action=" + action + ", target=" + targetUsername, "DENIED");
        throw new SecurityApiException(ErrorCode.FORBIDDEN, "无权操作他人资源");
    }

    public static String clientIp(HttpServletRequest request) {
        String ip = request.getHeader("X-Forwarded-For");
        if (ip == null || ip.isBlank()) {
            return request.getRemoteAddr();
        }
        return ip.split(",")[0].trim();
    }
}
