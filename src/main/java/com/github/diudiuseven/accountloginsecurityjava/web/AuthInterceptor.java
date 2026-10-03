package com.github.diudiuseven.accountloginsecurityjava.web;

import com.github.diudiuseven.accountloginsecurityjava.model.Account;
import com.github.diudiuseven.accountloginsecurityjava.model.Session;
import com.github.diudiuseven.accountloginsecurityjava.service.AccountService;
import com.github.diudiuseven.accountloginsecurityjava.service.AuditService;
import com.github.diudiuseven.accountloginsecurityjava.service.SessionService;
import com.github.diudiuseven.accountloginsecurityjava.web.dto.ApiError;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

/**
 * 认证拦截器：校验 Bearer 会话并写入请求属性。
 * 缺失/失效会话给出可区分拒绝原因（SESSION_EXPIRED / SESSION_REVOKED / ACCOUNT_BANNED）。
 */
@Component
public class AuthInterceptor implements HandlerInterceptor {

    private final SessionService sessionService;
    private final AccountService accountService;
    private final AuditService auditService;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public AuthInterceptor(SessionService sessionService, AccountService accountService,
                           AuditService auditService) {
        this.sessionService = sessionService;
        this.accountService = accountService;
        this.auditService = auditService;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
            throws Exception {
        if (!request.getRequestURI().startsWith("/api/")) {
            return true;
        }
        String token = resolveToken(request);
        SessionService.Validation v = sessionService.validate(token);
        if (!v.valid()) {
            String reason = v.reason();
            ErrorCode code;
            if (reason.startsWith("SESSION_EXPIRED")) {
                code = ErrorCode.SESSION_EXPIRED;
            } else if (reason.startsWith("ACCOUNT_BANNED")) {
                code = ErrorCode.ACCOUNT_BANNED;
            } else {
                code = ErrorCode.SESSION_REVOKED;
            }
            auditService.log(AuditService.UNAUTHORIZED_ACCESS,
                    token == null ? "-" : "token:" + abbreviate(token),
                    SecuritySupport.clientIp(request),
                    "uri=" + request.getMethod() + " " + request.getRequestURI() + ", reason=" + reason,
                    "REJECTED");
            writeError(response, HttpServletResponse.SC_UNAUTHORIZED, code, reason);
            return false;
        }
        Session session = v.session();
        Account account = accountService.getRequired(session.getUsername());
        request.setAttribute(SecuritySupport.ATTR_SESSION, session);
        request.setAttribute(SecuritySupport.ATTR_USERNAME, session.getUsername());
        request.setAttribute(SecuritySupport.ATTR_ROLE, account.getRole());
        return true;
    }

    private String resolveToken(HttpServletRequest request) {
        String header = request.getHeader("Authorization");
        if (header != null && header.startsWith("Bearer ")) {
            return header.substring(7).trim();
        }
        return null;
    }

    private void writeError(HttpServletResponse response, int status, ErrorCode code, String message)
            throws java.io.IOException {
        response.setStatus(status);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");
        objectMapper.writeValue(response.getWriter(), new ApiError(code.name(), message));
    }

    private String abbreviate(String token) {
        return token.length() <= 8 ? token : token.substring(0, 8) + "…";
    }
}
