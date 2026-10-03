package com.github.diudiuseven.accountloginsecurityjava.web.dto;

/** 登录请求。 */
public class LoginRequest {
    private String username;
    private String password;
    private String device;

    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
    public String getPassword() { return password; }
    public void setPassword(String password) { this.password = password; }
    public String getDevice() { return device; }
    public void setDevice(String device) { this.device = device; }
}
