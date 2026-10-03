package com.github.diudiuseven.accountloginsecurityjava.web.dto;

/** 管理员重置口令请求。 */
public class ResetPasswordRequest {
    private String newPassword;

    public String getNewPassword() { return newPassword; }
    public void setNewPassword(String newPassword) { this.newPassword = newPassword; }
}
