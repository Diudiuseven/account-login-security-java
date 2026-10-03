package com.github.diudiuseven.accountloginsecurityjava.config;

import com.github.diudiuseven.accountloginsecurityjava.model.Role;
import com.github.diudiuseven.accountloginsecurityjava.service.AccountService;
import com.github.diudiuseven.accountloginsecurityjava.store.SecurityStore;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

/** 启动时确保存在一个引导管理员账号（仅本进程内数据，不依赖外部服务）。 */
@Component
public class BootstrapAdminInitializer implements ApplicationRunner {

    private final SecurityStore store;
    private final AccountService accountService;
    private final SecurityProperties properties;

    public BootstrapAdminInitializer(SecurityStore store, AccountService accountService,
                                     SecurityProperties properties) {
        this.store = store;
        this.accountService = accountService;
        this.properties = properties;
    }

    @Override
    public void run(ApplicationArguments args) {
        String admin = properties.getBootstrapAdminUsername();
        if (store.getAccount(admin) == null) {
            accountService.createAccount(admin, properties.getBootstrapAdminPassword(), Role.ADMIN.name());
        }
    }
}
