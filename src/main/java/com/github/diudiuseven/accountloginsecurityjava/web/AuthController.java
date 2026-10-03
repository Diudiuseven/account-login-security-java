package com.github.diudiuseven.accountloginsecurityjava.web;

import com.github.diudiuseven.accountloginsecurityjava.model.LoginOutcome;
import com.github.diudiuseven.accountloginsecurityjava.model.Session;
import com.github.diudiuseven.accountloginsecurityjava.service.AuditService;
import com.github.diudiuseven.accountloginsecurityjava.service.LoginService;
import com.github.diudiuseven.accountloginsecurityjava.service.SessionService;
import com.github.diudiuseven.accountloginsecurityjava.web.dto.LoginRequest;
import com.github.diudiuseven.accountloginsecurityjava.web.dto.LoginResponse;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/** 认证接口：登录、注销、续期。 */
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final LoginService loginService;
    private final SessionService sessionService;
    private final AuditService auditService;

    public AuthController(LoginService loginService, SessionService sessionService, AuditService auditService) {
        this.loginService = loginService;
        this.sessionService = sessionService;
        this.auditService = auditService;
    }

    @PostMapping("/login")
    public Object login(@RequestBody LoginRequest request, HttpServletRequest httpRequest) {
        LoginService.LoginResult result = loginService.login(
                request.getUsername(), request.getPassword(),
                SecuritySupport.clientIp(httpRequest), request.getDevice());
        if (result.outcome() == LoginOutcome.SUCCESS) {
            return new LoginResponse(result.token(), request.getUsername());
        }
        ErrorCode code = switch (result.outcome()) {
            case BAD_CREDENTIALS -> ErrorCode.BAD_CREDENTIALS;
            case ACCOUNT_LOCKED -> ErrorCode.ACCOUNT_LOCKED;
            case ACCOUNT_BANNED -> ErrorCode.ACCOUNT_BANNED;
            default -> ErrorCode.BAD_CREDENTIALS;
        };
        throw new SecurityApiException(code, result.message());
    }

    @PostMapping("/logout")
    public Object logout(HttpServletRequest request) {
        Session session = SecuritySupport.currentSession(request);
        sessionService.revoke(session, SessionService.REASON_LOGOUT, SecuritySupport.clientIp(request));
        return Map.of("result", "ok");
    }

    @PostMapping("/renew")
    public Object renew(HttpServletRequest request) {
        Session session = SecuritySupport.currentSession(request);
        SessionService.Validation v = sessionService.renew(session.getToken());
        if (!v.valid()) {
            throw toException(v.reason());
        }
        return Map.of("result", "ok", "expiresAt", v.session().getExpiresAt());
    }

    static SecurityApiException toException(String reason) {
        if (reason.startsWith("SESSION_EXPIRED")) {
            return new SecurityApiException(ErrorCode.SESSION_EXPIRED, "会话已过期");
        }
        if (reason.startsWith("ACCOUNT_BANNED")) {
            return new SecurityApiException(ErrorCode.ACCOUNT_BANNED, "账号已被封禁");
        }
        return new SecurityApiException(ErrorCode.SESSION_REVOKED, "会话已失效");
    }
}
