# 账号登录凭据校验与会话安全（account-login-security-java）

一套完整的、**进程内自包含**的登录凭据校验与账号会话安全能力。
不依赖任何外部服务（无数据库、无 Redis、无消息队列），所有状态落盘到本地目录，
全部结论可在本地复现与验证。

---

## 一、能力总览

| 能力 | 说明 |
|------|------|
| 凭据设置与校验 | 口令仅以 **PBKDF2WithHmacSHA256 + 每口令随机盐** 的不可逆摘要保存；校验用 `MessageDigest.isEqual` 常量时间比较；明文口令不落盘、不进日志、不出现在任何错误信息/异常堆栈中。 |
| 失败节流与锁定 | 按**账号**与**来源 IP** 两个维度计数；连续失败窗口、阈值、锁定时长均可配置；并发失败在按 key 的条纹锁内收敛，**不多放行一次**；锁定到期自动恢复并清空计数。 |
| 会话签发/续期/注销 | 不透明随机令牌（32 字节 SecureRandom）；支持 **KICK_OUT（互相顶替）** 与 **MULTI（多端并存）** 两种策略；被顶替/被注销/被封禁的会话**立即失效**，拒绝原因可区分。 |
| 凭据变更/重置/封禁 | 改密、管理员重置、封禁/解封；敏感操作后相关会话按策略吊销；封禁期间登录一律拒绝；**解封后不得沿用封禁前签发的会话**（封禁时已吊销，不可恢复）。 |
| 可区分异常链路 | 不存在账号与错误口令返回**完全相同**的错误码与消息，且都执行一次 PBKDF2 以拉平耗时；会话过期/吊销/封禁返回不同错误码；越权请求被拒绝并写入审计，可追溯。 |
| 持久化与恢复 | 状态落盘到本地目录；写盘采用「临时文件 + fsync + 原子移动」，读者永远看不到半写文件；重启后已注销会话不复活、锁定不超过既定到期时间、未完成登录变为 **INTERRUPTED**（可区分）。 |
| 高并发 | 慢哈希在锁外执行，不同账号/IP 可并行；状态变更在按 key 的条纹锁内收敛；任意请求不读到半写状态。 |

---

## 二、安全语义

### 2.1 口令存储

- 算法：`PBKDF2WithHmacSHA256`，每口令 16 字节随机盐，迭代次数可配（默认 120_000）。
- 存储格式：`pbkdf2_sha256$<iterations>$<base64(salt)>$<base64(hash)>`。
- 校验：解析后用相同盐与迭代次数计算，`MessageDigest.isEqual` 常量时间比较。
- **明文口令的生命周期**：仅存在于登录请求的内存中，校验后即丢弃；不落盘、不进日志、不进异常信息。

### 2.2 失败节流与锁定

- 两个维度：`acct:<username>` 与 `ip:<clientIp>`。
- 每个维度独立计数：窗口起始时间 `windowStart`、窗口内失败数 `count`、锁定截止 `lockedUntil`。
- 判定：
  - 若 `lockedUntil > now` → 已锁定（仍执行一次哈希以拉平耗时）。
  - 否则若窗口已过期 → 重置计数。
  - 失败时 `count++`；当 `count > maxFailures`（即第 `maxFailures+1` 次）起锁定，`lockedUntil = now + lockDuration`。
- **并发收敛**：同一 key 的计数在 `synchronized` 条纹锁内执行。并发失败时，前 `maxFailures` 次返回 `BAD_CREDENTIALS`，其余全部返回 `ACCOUNT_LOCKED`，**不会多放行一次**。
- **到期恢复**：`lockedUntil <= now` 时惰性清空计数；窗口过期同样清空。

### 2.3 会话策略

- `KICK_OUT`（默认）：新登录吊销该账号全部旧会话（原因 `KICK_OUT`）。
- `MULTI`：多端并存，互不影响。
- 会话校验顺序：存在性 → 状态（REVOKED/EXPIRED）→ 过期时间 → 账号封禁状态。
- 拒绝原因：
  - `SESSION_EXPIRED`：会话过期。
  - `SESSION_REVOKED:<reason>`：会话被吊销，原因包括 `LOGOUT` / `KICK_OUT` / `CREDENTIAL_CHANGED` / `ADMIN_RESET` / `BANNED` / `INTERRUPTED_BY_RESTART`。
  - `ACCOUNT_BANNED`：账号被封禁。

### 2.4 凭据变更 / 封禁

- 改密（本人）：校验原口令 → 新口令哈希 → 按策略吊销全部会话（`CREDENTIAL_CHANGED`）。
- 重置（管理员）：新口令哈希 → 吊销全部会话（`ADMIN_RESET`）。
- 封禁（管理员）：账号置为 `BANNED` → 吊销全部会话（`BANNED`）。封禁期间登录返回 `ACCOUNT_BANNED`，会话校验返回 `SESSION_REVOKED:BANNED`。
- 解封（管理员）：账号恢复 `ACTIVE`。**封禁前签发的会话已被吊销，不可恢复**，仍返回 `SESSION_REVOKED:BANNED`。

### 2.5 信息泄露防护

- **账号枚举防护**：不存在账号与错误口令返回相同错误码 `BAD_CREDENTIALS` 与相同消息；且两者都执行一次 PBKDF2（不存在账号时使用预生成的哑摘要），响应耗时一致。
- **越权防护**：敏感操作（开户、封禁/解封、重置口令）仅管理员；查看/吊销他人会话需本人或管理员。越权返回 `FORBIDDEN` 并写入审计（`UNAUTHORIZED_ACCESS`，结果 `DENIED`）。
- **错误响应**：统一 JSON `{code, message}`，不泄露堆栈、不泄露内部细节。

### 2.6 重启恢复

- **已注销会话不复活**：会话状态持久化，重启后 `REVOKED` 状态保持。
- **锁定不超过既定到期时间**：重启时清理已过期的锁定（`lockedUntil <= now`）；未到期的锁定保持。
- **未完成登录可区分**：登录尝试记录（`LoginAttempt`）状态机 `PENDING → SUCCESS / FAILURE / INTERRUPTED`。重启时所有 `PENDING` 记录变为 `INTERRUPTED`，其已签发的会话吊销（`INTERRUPTED_BY_RESTART`）。
- **会话恢复**：未过期的 `ACTIVE` 会话默认恢复（可配 `restore-sessions-on-restart=false` 全部吊销）。

### 2.7 持久化与并发

- 存储目录：`security.store-dir`（默认 `./data/security`）。
- 文件：`accounts.json`、`sessions.json`、`failures.json`、`login-attempts.json`、`audit.log`（追加写）。
- 写盘：内存 `ConcurrentHashMap` 更新后，在 `writeLock` 串行化下写临时文件 → fsync → 原子移动 → fsync 目录。读者永远看不到半写文件。
- 进程锁：`.lock` 文件 + `FileLock` 防止多进程同时打开同一数据目录。
- 并发：慢哈希在锁外执行；状态变更在按 key 的条纹锁内收敛；落盘在全局写锁内串行。

---

## 三、配置项

在 `application.properties` 中配置（前缀 `security`）：

| 配置项 | 默认值 | 说明 |
|--------|--------|------|
| `security.store-dir` | `./data/security` | 持久化数据目录 |
| `security.password-hash-iterations` | `120000` | PBKDF2 迭代次数（测试可调低以加速） |
| `security.fail-window-ms` | `600000`（10 分钟） | 账号失败计数窗口（毫秒） |
| `security.max-failures` | `5` | 账号窗口内最大失败次数，第 N+1 次起锁定 |
| `security.lock-duration-ms` | `900000`（15 分钟） | 锁定时长（毫秒） |
| `security.ip-fail-window-ms` | `600000` | 来源 IP 失败计数窗口（毫秒） |
| `security.ip-max-failures` | `20` | 来源 IP 窗口内最大失败次数 |
| `security.session-ttl-ms` | `1800000`（30 分钟） | 会话有效期（毫秒） |
| `security.session-strategy` | `KICK_OUT` | 多端策略：`KICK_OUT` / `MULTI` |
| `security.revoke-on-credential-change` | `true` | 改密后是否吊销全部会话 |
| `security.restore-sessions-on-restart` | `true` | 重启后是否恢复未过期会话 |
| `security.bootstrap-admin-username` | `admin` | 引导管理员用户名 |
| `security.bootstrap-admin-password` | `admin123` | 引导管理员口令（生产务必修改） |

---

## 四、API 概览

| 方法 | 路径 | 认证 | 说明 |
|------|------|------|------|
| POST | `/api/auth/login` | 无 | 登录，返回 `{token, username}` |
| POST | `/api/auth/logout` | 会话 | 注销当前会话 |
| POST | `/api/auth/renew` | 会话 | 续期当前会话 |
| POST | `/api/accounts` | 管理员 | 开户 |
| POST | `/api/accounts/me/password` | 会话 | 本人改密 |
| POST | `/api/accounts/{username}/password/reset` | 管理员 | 重置他人口令 |
| POST | `/api/accounts/{username}/ban` | 管理员 | 封禁 |
| POST | `/api/accounts/{username}/unban` | 管理员 | 解封 |
| GET | `/api/sessions` | 会话 | 查询会话（本人或管理员） |
| DELETE | `/api/sessions/{token}` | 会话 | 吊销会话（本人或管理员） |

请求头：`Authorization: Bearer <token>`。

错误响应：`{"code": "<ERROR_CODE>", "message": "<描述>"}`。

错误码：`BAD_CREDENTIALS` / `ACCOUNT_LOCKED` / `ACCOUNT_BANNED` / `SESSION_EXPIRED` / `SESSION_REVOKED` / `UNAUTHORIZED` / `FORBIDDEN` / `NOT_FOUND` / `VALIDATION_ERROR` / `INTERNAL_ERROR`。

---

## 五、运行与测试

```bash
# 构建
mvn compile

# 运行（默认端口 8080，数据目录 ./data/security）
mvn spring-boot:run

# 自定义配置
mvn spring-boot:run -Dspring-boot.run.arguments="--server.port=8080 --security.store-dir=/path/to/data"

# 运行全部测试
mvn test
```

### 测试覆盖

| 测试类 | 覆盖场景 |
|--------|----------|
| `AccountLockoutTest` | 并发失败锁定收敛、锁定到期自动恢复并清空计数 |
| `IpLockoutTest` | 来源 IP 并发失败锁定收敛 |
| `SessionStrategyTest` | KICK_OUT 顶替、注销立即失效、改密吊销会话 |
| `MultiSessionTest` | MULTI 多端并存 |
| `BanUnbanTest` | 封禁拒绝登录并吊销会话、解封后旧会话不恢复 |
| `AuthorizationAndLeakTest` | 不存在账号与错误口令响应一致且耗时一致、越权拒绝并审计 |
| `RestartRecoveryTest` | 重启后已注销不复活、锁定保持、未完成登录变为 INTERRUPTED |
| `ConcurrentBanAndLoginTest` | 并发登录与封禁无 5xx、封禁后登录全部拒绝 |

---

## 六、安全设计小结

1. **口令不可逆**：PBKDF2 + 随机盐，常量时间比较。
2. **明文口令零暴露**：不落盘、不进日志、不进异常。
3. **失败锁定收敛**：按 key 条纹锁，并发下不多放行。
4. **会话可区分**：被顶替/注销/封禁/过期原因明确。
5. **封禁不复活**：封禁即吊销，解封不恢复。
6. **账号枚举防护**：错误内容与耗时一致。
7. **越权可追溯**：敏感操作鉴权 + 审计。
8. **重启可解释**：未完成登录 INTERRUPTED，已注销不复活，锁定不超期。
9. **并发无半写**：原子落盘 + 条纹锁 + 慢哈希锁外执行。
