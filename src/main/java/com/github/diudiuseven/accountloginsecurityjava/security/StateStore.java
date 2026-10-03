package com.github.diudiuseven.accountloginsecurityjava.security;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.annotation.PreDestroy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * 状态持久化与恢复。JSON 落盘，写盘为 临时文件 + 原子 rename，
 * 读者永远看到完整文件，不会读到写了一半的中间状态。
 * 异步落盘带防抖，慢磁盘不阻塞登录主链路；进程关闭时冲刷未完成的写入。
 */
@Component
public class StateStore {

    private static final Logger log = LoggerFactory.getLogger(StateStore.class);

    private final SecurityProperties properties;
    private final ObjectMapper mapper = new ObjectMapper();
    private final ScheduledExecutorService executor;
    private final Object persistLock = new Object();
    private ScheduledFuture<?> pending;

    public StateStore(SecurityProperties properties) {
        this.properties = properties;
        this.executor = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "state-store-persister");
            t.setDaemon(true);
            return t;
        });
    }

    public boolean isEnabled() {
        return properties.getStateFile() != null && !properties.getStateFile().isBlank();
    }

    /** 请求一次异步落盘（防抖合并，慢操作不阻塞调用方）。 */
    public void requestPersist(Supplier<PersistedState> snapshotSupplier) {
        if (!isEnabled()) {
            return;
        }
        synchronized (persistLock) {
            if (pending != null && !pending.isDone()) {
                pending.cancel(false);
            }
            pending = executor.schedule(
                    () -> persistQuietly(snapshotSupplier),
                    properties.getPersistInterval().toMillis(), TimeUnit.MILLISECONDS);
        }
    }

    /** 立即同步落盘一次。 */
    public void persistNow(Supplier<PersistedState> snapshotSupplier) {
        if (!isEnabled()) {
            return;
        }
        persistQuietly(snapshotSupplier);
    }

    private void persistQuietly(Supplier<PersistedState> snapshotSupplier) {
        try {
            PersistedState state = snapshotSupplier.get();
            Path target = Path.of(properties.getStateFile());
            Path temp = target.resolveSibling(target.getFileName() + ".tmp");
            if (target.getParent() != null) {
                Files.createDirectories(target.getParent());
            }
            mapper.writeValue(temp.toFile(), state);
            Files.move(temp, target, StandardCopyOption.REPLACE_EXISTING,
                    StandardCopyOption.ATOMIC_MOVE);
        } catch (IOException | UncheckedIOException e) {
            // 落盘失败不携带任何敏感状态，只记录路径与错误类型
            log.warn("state persist failed: {}", e.getClass().getSimpleName());
        }
    }

    /** 启动时加载；文件不存在或损坏时返回 null（视为全新状态，可解释）。 */
    public PersistedState load() {
        if (!isEnabled()) {
            return null;
        }
        Path target = Path.of(properties.getStateFile());
        if (!Files.exists(target)) {
            return null;
        }
        try {
            return mapper.readValue(target.toFile(), PersistedState.class);
        } catch (IOException e) {
            log.warn("state load failed, starting fresh: {}", e.getClass().getSimpleName());
            return null;
        }
    }

    /** 进程关闭：冲刷未完成的落盘，保证已发生的注销/锁定不丢失。 */
    @PreDestroy
    public void shutdown() {
        synchronized (persistLock) {
            if (pending != null && !pending.isDone()) {
                pending.cancel(false);
                pending = null;
            }
        }
        executor.shutdown();
        try {
            executor.awaitTermination(2, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
