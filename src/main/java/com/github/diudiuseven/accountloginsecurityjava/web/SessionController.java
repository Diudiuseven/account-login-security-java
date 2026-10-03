package com.github.diudiuseven.accountloginsecurityjava.web;

import com.github.diudiuseven.accountloginsecurityjava.model.Session;
import com.github.diudiuseven.accountloginsecurityjava.service.AuditService;
import com.github.diudiuseven.accountloginsecurityjava.service.SessionService;
import com.github.diudiuseven.accountloginsecurityjava.web.dto.SessionResponse;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/** 会话查询与吊销接口。 */
@RestController
@RequestMapping("/api/sessions")
public class SessionController {

    private final SessionService sessionService;
    private final AuditService auditService;

    public SessionController(SessionService sessionService, AuditService auditService) {
        this.sessionService = sessionService;
        this.auditService = auditService;
    }

    @GetMapping
    public Object list(@RequestParam(required = false) String username, HttpServletRequest request) {
        String self = SecuritySupport.currentUsername(request);
        String target = (username == null || username.isBlank()) ? self : username;
        SecuritySupport.requireSelfOrAdmin(request, auditService, target, "session:list");
        List<SessionResponse> result = sessionService.listForUser(target).stream()
                .map(s -> toResponse(s, self.equals(s.getUsername())))
                .toList();
        return result;
    }

    @DeleteMapping("/{token}")
    public Object revoke(@PathVariable String token, HttpServletRequest request) {
        Session session = sessionService.validate(token).session();
        if (session == null) {
            throw new SecurityApiException(ErrorCode.NOT_FOUND, "会话不存在或已失效");
        }
        SecuritySupport.requireSelfOrAdmin(request, auditService, session.getUsername(), "session:revoke");
        sessionService.revoke(session, SessionService.REASON_LOGOUT, SecuritySupport.clientIp(request));
        return Map.of("result", "ok");
    }

    private SessionResponse toResponse(Session s, boolean owner) {
        SessionResponse r = new SessionResponse();
        // 令牌是持有者密钥：列表中只返回前缀，避免泄露给他人
        r.setToken(owner ? s.getToken() : abbreviate(s.getToken()));
        r.setUsername(s.getUsername());
        r.setIssuedAt(s.getIssuedAt());
        r.setExpiresAt(s.getExpiresAt());
        r.setStatus(s.getStatus().name());
        r.setDevice(s.getDevice());
        r.setIp(s.getIp());
        r.setRevokeReason(s.getRevokeReason());
        return r;
    }

    private String abbreviate(String token) {
        return token.length() <= 8 ? token : token.substring(0, 8) + "…";
    }
}
