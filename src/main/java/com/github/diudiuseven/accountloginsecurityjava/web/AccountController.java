package com.github.diudiuseven.accountloginsecurityjava.web;

import com.github.diudiuseven.accountloginsecurityjava.model.Account;
import com.github.diudiuseven.accountloginsecurityjava.service.AccountService;
import com.github.diudiuseven.accountloginsecurityjava.service.AuditService;
import com.github.diudiuseven.accountloginsecurityjava.web.dto.AccountResponse;
import com.github.diudiuseven.accountloginsecurityjava.web.dto.CreateAccountRequest;
import com.github.diudiuseven.accountloginsecurityjava.web.dto.PasswordChangeRequest;
import com.github.diudiuseven.accountloginsecurityjava.web.dto.ResetPasswordRequest;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/** 账号管理接口：开户、改密、重置、封禁/解封。 */
@RestController
@RequestMapping("/api/accounts")
public class AccountController {

    private final AccountService accountService;
    private final AuditService auditService;

    public AccountController(AccountService accountService, AuditService auditService) {
        this.accountService = accountService;
        this.auditService = auditService;
    }

    @PostMapping
    public Object create(@RequestBody CreateAccountRequest request, HttpServletRequest httpRequest) {
        SecuritySupport.requireAdmin(httpRequest, auditService, "account:create");
        Account account = accountService.createAccount(request.getUsername(), request.getPassword(), request.getRole());
        return toResponse(account);
    }

    @PostMapping("/me/password")
    public Object changeMyPassword(@RequestBody PasswordChangeRequest request, HttpServletRequest httpRequest) {
        String username = SecuritySupport.currentUsername(httpRequest);
        accountService.changePassword(username, request.getOldPassword(), request.getNewPassword());
        return Map.of("result", "ok");
    }

    @PostMapping("/{username}/password/reset")
    public Object resetPassword(@PathVariable String username,
                                @RequestBody ResetPasswordRequest request,
                                HttpServletRequest httpRequest) {
        SecuritySupport.requireAdmin(httpRequest, auditService, "account:resetPassword");
        accountService.resetPassword(username, request.getNewPassword(),
                SecuritySupport.currentUsername(httpRequest));
        return Map.of("result", "ok");
    }

    @PostMapping("/{username}/ban")
    public Object ban(@PathVariable String username, HttpServletRequest httpRequest) {
        SecuritySupport.requireAdmin(httpRequest, auditService, "account:ban");
        accountService.ban(username, SecuritySupport.currentUsername(httpRequest));
        return Map.of("result", "ok");
    }

    @PostMapping("/{username}/unban")
    public Object unban(@PathVariable String username, HttpServletRequest httpRequest) {
        SecuritySupport.requireAdmin(httpRequest, auditService, "account:unban");
        accountService.unban(username, SecuritySupport.currentUsername(httpRequest));
        return Map.of("result", "ok");
    }

    static AccountResponse toResponse(Account account) {
        return new AccountResponse(account.getUsername(), account.getRole().name(), account.getStatus().name());
    }
}
