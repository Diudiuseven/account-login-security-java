package com.github.diudiuseven.accountloginsecurityjava.store;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.diudiuseven.accountloginsecurityjava.config.SecurityProperties;
import com.github.diudiuseven.accountloginsecurityjava.model.Account;
import com.github.diudiuseven.accountloginsecurityjava.model.AuditEvent;
import com.github.diudiuseven.accountloginsecurityjava.model.FailureRecord;
import com.github.diudiuseven.accountloginsecurityjava.model.LoginAttempt;
import com.github.diudiuseven.accountloginsecurityjava.model.Session;
import com.github.diudiuseven.accountloginsecurityjava.model.SessionStatus;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;

/**
 * 基于本地文件的安全存储：内存并发映射 + 原子文件持久化。
 * <ul>
 *   <li>写盘采用“临时文件 + fsync + 原子移动”，读者永远不会看到半写文件；</li>
 *   <li>文件锁 .lock 防止多进程同时打开同一数据目录；</li>
 *   <li>启动时执行崩溃恢复：中断未完成登录、吊销其会话、清理过期锁定。</li>
 * </ul>
 */
@Component
public class FileSecurityStore implements SecurityStore {

    private static final String ACCOUNTS_FILE = "accounts.json";
    private static final String SESSIONS_FILE = "sessions.json";
    private static final String FAILURES_FILE = "failures.json";
    private static final String ATTEMPTS_FILE = "login-attempts.json";
    private static final String AUDIT_FILE = "audit.log";
    private static final String LOCK_FILE = ".lock";

    private final SecurityProperties properties;
    private final ObjectMapper objectMapper = new ObjectMapper();

    private final Map<String, Account> accounts = new ConcurrentHashMap<>();
    private final Map<String, Session> sessions = new ConcurrentHashMap<>();
    private final Map<String, FailureRecord> failures = new ConcurrentHashMap<>();
    private final Map<String, LoginAttempt> loginAttempts = new ConcurrentHashMap<>();
    private final List<AuditEvent> auditEvents = new ArrayList<>();

    /** 串行化所有落盘动作；状态逻辑本身不持此锁，慢操作（口令哈希）不受影响。 */
    private final ReentrantLock writeLock = new ReentrantLock();

    private FileLock fileLock;
    private Path dir;

    public FileSecurityStore(SecurityProperties properties) {
        this.properties = properties;
    }

    @PostConstruct
    @Override
    public void init() {
        try {
            dir = Paths.get(properties.getStoreDir());
            Files.createDirectories(dir);
            acquireProcessLock();
            loadAll();
            recover();
            appendAuditEvent("SYSTEM_START", "-", "-",
                    "storeDir=" + dir.toAbsolutePath(), "SUCCESS");
        } catch (IOException e) {
            throw new IllegalStateException("failed to initialize security store: " + dir, e);
        }
    }

    @PreDestroy
    public void shutdown() {
        writeLock.lock();
        try {
            flushAll();
            if (fileLock != null && fileLock.isValid()) {
                fileLock.release();
            }
        } catch (IOException e) {
            // 关闭时释放锁失败不影响退出
        } finally {
            writeLock.unlock();
        }
    }

    // ---------------- 读取（纯内存，无锁） ----------------

    @Override
    public Account getAccount(String username) {
        return username == null ? null : accounts.get(username);
    }

    @Override
    public Collection<Account> listAccounts() {
        return List.copyOf(accounts.values());
    }

    @Override
    public Session getSession(String token) {
        return token == null ? null : sessions.get(token);
    }

    @Override
    public Collection<Session> listSessions() {
        return List.copyOf(sessions.values());
    }

    @Override
    public List<Session> listSessionsByUsername(String username) {
        List<Session> result = new ArrayList<>();
        for (Session s : sessions.values()) {
            if (username.equals(s.getUsername())) {
                result.add(s);
            }
        }
        return result;
    }

    @Override
    public FailureRecord getFailure(String key) {
        return key == null ? null : failures.get(key);
    }

    @Override
    public Collection<FailureRecord> listFailures() {
        return List.copyOf(failures.values());
    }

    @Override
    public LoginAttempt getLoginAttempt(String attemptId) {
        return attemptId == null ? null : loginAttempts.get(attemptId);
    }

    @Override
    public Collection<LoginAttempt> listLoginAttempts() {
        return List.copyOf(loginAttempts.values());
    }

    // ---------------- 写入（更新内存后原子落盘） ----------------

    @Override
    public void putAccount(Account account) {
        accounts.put(account.getUsername(), account);
        persist(ACCOUNTS_FILE, accounts);
    }

    @Override
    public void putSession(Session session) {
        sessions.put(session.getToken(), session);
        persist(SESSIONS_FILE, sessions);
    }

    @Override
    public void putFailure(FailureRecord record) {
        failures.put(record.getKey(), record);
        persist(FAILURES_FILE, failures);
    }

    @Override
    public void removeFailure(String key) {
        if (failures.remove(key) != null) {
            persist(FAILURES_FILE, failures);
        }
    }

    @Override
    public void putLoginAttempt(LoginAttempt attempt) {
        loginAttempts.put(attempt.getAttemptId(), attempt);
        persist(ATTEMPTS_FILE, loginAttempts);
    }

    @Override
    public void appendAudit(AuditEvent event) {
        writeLock.lock();
        try {
            auditEvents.add(event);
            String line = objectMapper.writeValueAsString(event) + System.lineSeparator();
            Files.writeString(dir.resolve(AUDIT_FILE), line,
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND, StandardOpenOption.WRITE);
        } catch (IOException e) {
            throw new IllegalStateException("failed to append audit log", e);
        } finally {
            writeLock.unlock();
        }
    }

    // ---------------- 加载与恢复 ----------------

    private void loadAll() throws IOException {
        accounts.putAll(readMap(ACCOUNTS_FILE, new TypeReference<Map<String, Account>>() {}));
        sessions.putAll(readMap(SESSIONS_FILE, new TypeReference<Map<String, Session>>() {}));
        failures.putAll(readMap(FAILURES_FILE, new TypeReference<Map<String, FailureRecord>>() {}));
        loginAttempts.putAll(readMap(ATTEMPTS_FILE, new TypeReference<Map<String, LoginAttempt>>() {}));
    }

    private void recover() {
        long now = System.currentTimeMillis();

        // 1) 失败计数：锁定到期立即清空计数（锁定不得超过既定到期时间）；窗口过期也清空
        for (FailureRecord f : new ArrayList<>(failures.values())) {
            long window = f.getKind() == FailureRecord.Kind.IP
                    ? properties.getIpFailWindowMs() : properties.getFailWindowMs();
            boolean lockExpired = f.getLockedUntil() > 0 && f.getLockedUntil() <= now;
            boolean windowExpired = f.getWindowStart() > 0 && now - f.getWindowStart() > window;
            if (lockExpired || windowExpired) {
                f.setCount(0);
                f.setLockedUntil(0);
                f.setWindowStart(0);
                putFailure(f);
            }
        }

        // 2) 未完成登录：PENDING -> INTERRUPTED，并吊销其已签发的会话
        for (LoginAttempt a : new ArrayList<>(loginAttempts.values())) {
            if (a.getStatus() == LoginAttempt.Status.PENDING) {
                a.setStatus(LoginAttempt.Status.INTERRUPTED);
                a.setReason("interrupted by restart");
                putLoginAttempt(a);
                if (a.getSessionToken() != null) {
                    Session s = sessions.get(a.getSessionToken());
                    if (s != null && s.getStatus() == SessionStatus.ACTIVE) {
                        s.setStatus(SessionStatus.REVOKED);
                        s.setRevokeReason("INTERRUPTED_BY_RESTART");
                        putSession(s);
                    }
                }
            }
        }

        // 3) 会话：过期的标记 EXPIRED；按策略决定是否恢复 ACTIVE 会话
        for (Session s : new ArrayList<>(sessions.values())) {
            if (s.getStatus() == SessionStatus.ACTIVE && s.getExpiresAt() <= now) {
                s.setStatus(SessionStatus.EXPIRED);
                putSession(s);
            } else if (s.getStatus() == SessionStatus.ACTIVE && !properties.isRestoreSessionsOnRestart()) {
                s.setStatus(SessionStatus.REVOKED);
                s.setRevokeReason("RESTART_POLICY");
                putSession(s);
            }
        }
    }

    // ---------------- 持久化原语 ----------------

    private <T> Map<String, T> readMap(String file, TypeReference<Map<String, T>> typeRef) throws IOException {
        Path p = dir.resolve(file);
        if (!Files.exists(p)) {
            return new HashMap<>();
        }
        return objectMapper.readValue(Files.readString(p), typeRef);
    }

    private void persist(String file, Map<String, ?> data) {
        writeLock.lock();
        try {
            Path target = dir.resolve(file);
            Path tmp = dir.resolve(file + ".tmp");
            byte[] bytes = objectMapper.writeValueAsBytes(data);
            Files.write(tmp, bytes, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE);
            fsync(tmp);
            try {
                Files.move(tmp, target,
                        java.nio.file.StandardCopyOption.ATOMIC_MOVE,
                        java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            } catch (IOException atomicMoveUnsupported) {
                Files.move(tmp, target,
                        java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            }
            fsyncDirectory();
        } catch (IOException e) {
            throw new IllegalStateException("failed to persist " + file, e);
        } finally {
            writeLock.unlock();
        }
    }

    private void flushAll() {
        persist(ACCOUNTS_FILE, accounts);
        persist(SESSIONS_FILE, sessions);
        persist(FAILURES_FILE, failures);
        persist(ATTEMPTS_FILE, loginAttempts);
    }

    private void fsync(Path path) throws IOException {
        try (FileChannel ch = FileChannel.open(path, StandardOpenOption.READ)) {
            ch.force(true);
        }
    }

    private void fsyncDirectory() {
        try (FileChannel ch = FileChannel.open(dir, StandardOpenOption.READ)) {
            ch.force(true);
        } catch (IOException ignored) {
            // 某些平台不支持目录 fsync，忽略即可
        }
    }

    private void acquireProcessLock() throws IOException {
        Path lockPath = dir.resolve(LOCK_FILE);
        FileChannel channel = FileChannel.open(lockPath,
                StandardOpenOption.CREATE, StandardOpenOption.WRITE);
        fileLock = channel.tryLock();
        if (fileLock == null) {
            channel.close();
            throw new IllegalStateException(
                    "security store directory is locked by another process: " + dir.toAbsolutePath());
        }
    }

    private void appendAuditEvent(String eventType, String username, String ip, String detail, String result) {
        AuditEvent e = new AuditEvent();
        e.setTimestamp(System.currentTimeMillis());
        e.setEventType(eventType);
        e.setUsername(username);
        e.setIp(ip);
        e.setDetail(detail);
        e.setResult(result);
        appendAudit(e);
    }
}
