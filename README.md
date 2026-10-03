# account-login-security-java

进程内登录凭据校验与账号会话安全能力。整条链路只在本进程内运行，
不依赖任何外部服务，全部结论可在本地复现与验证。

## 构建与测试

```bash
mvn compile   # 编译
mvn test      # 运行全部测试（含并发、重启恢复等场景）
mvn spring-boot:run  # 启动 HTTP 服务（默认随机端口）
```

## 架构

```
security/
├── SecurityProperties   配置项（阈值/窗口/锁定时长/会话TTL/多端策略/持久化）
├── PasswordHasher       PBKDF2-HmacSHA256 不可逆摘要，常数时间比较
├── CredentialStore      凭据存储（只存摘要），未知账号走哑摘要保证等耗时
├── LockoutManager       失败节流与临时锁定（账号/来源双维度）
├── SessionManager       会话签发/续期/注销/多端顶替（墓碑防复活）
├── AuthService          编排入口：登录、改密、重置、封禁、解封、鉴权
├── AuditLog             安全审计（越权与敏感操作可追溯，绝不含口令）
├── StateStore           JSON 原子落盘（临时文件+rename），异步防抖
└── api/                 REST 入口与统一异常映射
```

## 安全语义

### 凭据
- 口令只以 PBKDF2-HmacSHA256 摘要（随机盐、可配迭代次数）保存，
  格式 `iterations:salt:hash`；明文不落盘、不进日志、不出现在异常中。
- 摘要用 `MessageDigest.isEqual` 常数时间比较；账号不存在时对预计算的
  哑摘要执行同样的运算，校验耗时不泄露账号是否存在。

### 登录失败与信息泄露
- 不存在的账号、错误口令、已锁定、已封禁四种失败对外返回**完全相同的**
  状态码（401）与错误体（`invalid_credentials`），且都执行相同的摘要运算，
  响应耗时不泄露账号存在性。
- 内部审计（`AuditLog`）保留真实失败原因以便追溯，但绝不记录口令。

### 节流与锁定
- 按账号与来源两个维度统计滑动窗口内的失败次数，达到阈值即锁定。
- 同一键上的状态变更在该键的监视器上串行化，并发失败收敛到同一个
  锁定结果，不会因竞态多放行一次。
- 锁定到期自动解除并清空计数；登录成功立即清空该账号与来源的计数。

### 会话
- 令牌为 256 位随机不透明串。支持续期与注销。
- 多端策略可配：并存（`allowConcurrentSessions=true`）或顶替（默认，
  新登录原子地将同账号旧会话置为 SUPERSEDED）。
- 会话拒绝原因可区分：`session_invalid` / `session_expired` /
  `session_revoked`（注销）/ `session_superseded`（被顶替）/
  `session_invalidated`（敏感操作后失效）。
- 被注销/被顶替的会话保留墓碑直到原定到期时间，进程重启后不会复活。

### 敏感操作与授权
- 改密需本人会话 + 旧口令；重置/封禁/解封需 `ADMIN` 角色会话。
- 越权请求返回 403 并写入审计（行为者、目标、结果），可追溯。
- 改密/重置/封禁完成后，目标账号全部会话立即失效；凭据版本号递增，
  旧版本签发的会话一律视为失效。
- 封禁期间登录全部拒绝（对外仍是统一错误）；解封不恢复封禁前的会话。

### 持久化与重启
- 状态（凭据摘要、会话含墓碑、锁定）以 JSON 原子落盘
  （临时文件 + `ATOMIC_MOVE` rename），读者不会看到写了一半的文件。
- 落盘异步防抖执行，慢磁盘不阻塞登录主链路；进程关闭时冲刷未完成的写入。
- 重启恢复时：已到期会话与锁定直接丢弃（锁定绝不超过既定到期时间），
  未到期状态原样恢复；状态文件缺失或损坏时可解释地降级为全新状态。

### 并发
- 凭据校验为无锁只读；锁定计数按键串行化；会话状态变更通过
  `ConcurrentHashMap` 原子完成；同账号签发/顶替在账号锁上串行化。
- 任意请求读到的都是完整状态，最终结果确定且可解释。

## 配置项（`security.auth.*`）

| 配置 | 默认值 | 说明 |
|---|---|---|
| `hash-iterations` | 120000 | PBKDF2 迭代次数 |
| `failure-window` | 10m | 连续失败统计窗口 |
| `max-failures` | 5 | 窗口内触发锁定的失败次数 |
| `lock-duration` | 15m | 锁定时长 |
| `session-ttl` | 2h | 会话有效期 |
| `allow-concurrent-sessions` | false | 多端并存（true）或顶替（false） |
| `state-file` | 空 | 状态持久化文件路径，空表示仅内存 |
| `persist-interval` | 200ms | 异步落盘防抖间隔 |

## REST API

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/auth/login` | 登录，返回 `{token, accountId, expiresAt}` |
| POST | `/api/auth/logout` | 注销（头 `X-Session-Token`） |
| POST | `/api/auth/renew` | 续期 |
| GET | `/api/auth/whoami` | 校验会话并返回账号 |
| POST | `/api/auth/password/change` | 本人改密（需旧口令） |
| POST | `/api/auth/password/reset` | 管理员重置口令 |
| POST | `/api/auth/ban` / `/unban` | 管理员封禁/解封 |
| GET | `/api/auth/audit` | 管理员查看审计事件 |

登录失败统一返回 `401 {"error":"invalid_credentials"}`；
会话失败返回 `401 {"error":"session_*"}`（原因可区分）；
越权返回 `403 {"error":"forbidden"}`。

## 测试覆盖

- `CredentialSecurityTest`：摘要不可逆、随机盐、明文不落盘、错误信息无敏感内容、校验耗时一致
- `LockoutConcurrencyTest`：并发失败收敛、不多放行、到期恢复清空计数、双维度锁定、可配置阈值
- `SessionLifecycleTest`：多端顶替/并存、注销与过期原因可区分、并发顶替只剩一个活跃会话
- `BanAndCredentialChangeTest`：封禁/解封、改密/重置后会话失效、越权拒绝并留痕
- `InformationLeakTest`：四种登录失败错误内容与耗时一致、审计保留真实原因且不含口令
- `PersistenceRecoveryTest`：注销不复活、锁定不超期、封禁跨重启生效、损坏文件可解释降级
- `HighConcurrencyTest`：登录+重置+封禁并发、慢摘要不拖垮吞吐、快照无中间状态
