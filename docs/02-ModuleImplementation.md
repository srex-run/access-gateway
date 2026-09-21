# 模块实现

[项目首页](../README.md) · [架构设计](01-ArchitectureDesign.md) · [本地开发](03-LocalDevelopment.md) · [部署运维](04-Deployment.md)

## 代码组织

| 路径 | 职责 |
| --- | --- |
| `cmd/access-gateway`、`internal/app` | 启动、配置加载、依赖组装、HTTP 和 Worker 生命周期 |
| `internal/httpapi` | HTTP 路由、输入输出、CSRF、认证、RBAC 和加密传输边界 |
| `internal/service` | 业务权限、审批与会话状态机、事务、补偿及审计关联 |
| `internal/repository`、`internal/db` | SQL、显式字段映射、驱动注册和连接池 |
| `internal/domain` | 领域对象、状态与审计类型 |
| `internal/authn`、`security`、`iam`、`authz`、`label` | 登录、MFA、角色权限与标签匹配 |
| `internal/sessionruntime`、`gateway`、`gatewayagent` | 会话调度合同、运行时、Agent 管理和连接控制 |
| `internal/sessionproxy`、`terminal`、`terminalclient` | 协议审计、终端传输及受限原生客户端 |
| `internal/securetransport`、`secretstore`、`settings` | 浏览器信封、静态加密与系统配置 |
| `internal/cloudassets`、`cmdb`、`feishu`、`mailer` | 外部资产、认证渠道和通知集成 |
| `internal/worker`、`realtime`、`observability` | 异步任务、SSE 信号、指标与追踪 |
| `internal/managementconsole` | 服务 React 构建产物并设置 CSP 等响应头 |
| `internal/bootstrap`、`migrations` | 首次管理员初始化、版本化数据库迁移 |
| `apps/web` | React 控制台、共享 API 客户端和页面测试 |

主要依赖方向为 `httpapi → service → repository/domain`，外部能力通过接口接入。数据层使用 PostgreSQL、`database/sql` 和 pgx 驱动，不使用 ORM；查询列与扫描顺序必须对应，事务由 service 管理。完整约束见 [agent.md](../agent.md)。

## 身份、用户与权限

本地账户始终保留登录入口。OIDC、LDAP、OAuth2、GitHub 和飞书可在系统设置启用；外部身份按提供方、issuer 和 subject 关联，不凭同邮箱自动合并。本地用户名与昵称分开保存。

`PUBLIC_URL` 自动生成回调地址，例如 `/api/v1/auth/github/callback`。浏览器必须使用配置的完整来源，`localhost` 与 `127.0.0.1` 不等价。生产禁用 `ALLOW_DEV_AUTH`；开发的 `X-User-ID` 仍必须对应启用用户。

邮箱邀请由具有 `user:manage` 的用户创建，可重发或撤销。SMTP 未启用或发送失败时可复制一次性链接。MFA 支持 TOTP 和单次恢复码，策略包括自愿绑定、管理员强制、全员强制；管理员判断使用 `role:manage`。登录提供方验证成功后仍须满足 MFA 策略，重置 MFA 会使旧登录状态失效。

| 内置角色 | 默认用途 |
| --- | --- |
| `admin` | 全部已知权限；保持启用并保留 `role:manage` |
| `auditor` | 目录、个人申请与会话、审批和审计，可调整或停用 |
| `user` | 所有账户的基础角色：目录、个人申请和个人会话 |

角色是平铺集合，没有继承；标签本身不授予权限。显式标签绑定将用户选择器匹配到角色选择器，权限目录在 [`internal/authz/catalog.go`](../internal/authz/catalog.go)。授权变更使用 revision 检查并记录审计；系统托管标签前缀为 `access-gateway.io/`。

## 资产目录与审批流程

资产包含区域、目标地址、类型、风险级别、TTL 上限、TCP 端口及对应协议。目标地址加密保存，普通查询不返回目标明文或密文。删除资产会停用并隐藏目录项、排队回收活动会话，历史申请与审计继续保留。

资产直接关联一个有效审批流程。流程可以包含负责人、用户选择器、角色选择器等节点；负责人规则通过资源标签匹配。审批快照固定当前申请的节点与审批人，编辑流程不会重写已提交申请。负责人必须同时具备审批权限，管理员身份也不能绕过禁止自批规则。

申请必须携带幂等键；手动重试相同提交内容时复用该键。后台启动与回收通过 outbox 执行，详细时序见[架构设计](01-ArchitectureDesign.md#申请审批与回收)。

云资产接入支持阿里云、AWS、华为云，通过云账号和同步任务导入云主机。云账号密钥加密保存，编辑时留空保留原值，轮换时同时更新 AK/SK。导入后需确认端口、协议、目标信任及审批流程，不能把成功同步视为已具备访问条件。

CMDB 接入通过 `CMDB_URL` 与 `CMDB_BEARER_TOKEN[_FILE]` 配置。接口返回 `version: 1`、`authoritative: true`、一致的 `revision`、资产数组及 `next_cursor`；客户端限制分页和体积并拒绝跳转。后台使用 advisory lock 防止重复同步，权威快照中消失或停用的资产触发访问回收。分页结构以 [`internal/cmdb/client.go`](../internal/cmdb/client.go) 为准。

## 会话连接与站内终端

`internal/sessionruntime` 实现 local、Docker 和 Kubernetes 调度，Agent 执行已经固定的授权。连接模式只有两个可创建值：

| 模式 | 数据路径 | 可用入口 | 审计内容 |
| --- | --- | --- | --- |
| `native` | 客户端与目标端到端 SSH/TLS | 本地客户端 | 连接、来源、流量、生命周期 |
| `audit` | Agent 终止并重新建立 SSH/TLS | 站内终端和可选本地客户端 | 连接、协议操作及终端输出 |

在资产的“连接与审计”中配置每个端口。开启操作审计后，可以使用“一键生成全部”生成 Agent 身份并探测目标 TLS 证书或 SSH 主机公钥。目标必须已经支持 TLS/SSH；生成配置不会替目标服务启用 TLS。目标证书更换后需要更新信任配置并重新申请会话。

| 协议 | 站内客户端 | 主要审计证据 |
| --- | --- | --- |
| SSH / SSHD | Go SSH 客户端、真实 shell 与 PTY | exec、退出结果、交互输出、SFTP 操作 |
| MySQL / MariaDB | `mariadb` / `mysql` | 查询、预处理操作及结果，参数脱敏 |
| PostgreSQL | `psql` | 简单与扩展查询、事务结果 |
| Redis | `redis-cli` | 命令及事务结果，参数脱敏 |
| MongoDB | `mongosh` | 支持的 OP_MSG 操作及结果，不记录文档正文 |
| HTTP / HTTPS | Bash / `curl` 请求终端 | 方法、路径和状态，不记录认证头及正文 |

站内终端要求会话申请人身份、有效登录、权限、同源 Origin 和未到期授权。目标账号来自已批准申请，登录首帧通过一次性加密信封传递密码、SSH 私钥等数据；控制平面通过私有 mTLS 转交 Agent，不把凭据写入 URL、日志、数据库或持久化授权文件。

SSH 使用目标账号的真实 shell。数据库与 HTTP 客户端在会话 worker 的 PTY 内运行；Linux 使用 Landlock 与 seccomp 限制文件和网络访问，macOS 开发使用系统沙箱。支持窗口调整、Ctrl+C、Tab、全屏程序及 UTF-8 流。断开后可以在授权有效期内重新连接，但不恢复已经退出的 shell。

审计协议并非任意 TCP 代理：SSH forwarding、HTTP CONNECT/升级、Redis 复制或订阅等未支持能力会被拒绝。客户端仍需满足目标服务的账号权限。

## 审计、通知与实时更新

平台操作日志记录用户、角色、资源、审批和设置变更。会话记录保存连接、流量、回收轨迹和协议操作。终端输出按会话、终端编号和片段序号保存，页面按需读取并使用只读 xterm 回放；输出不等于逐条命令执行证明，也不主动记录原始键盘输入。

MySQL 首次提示符前的固定版本探测与语法探测标为客户端初始化证据，不计入用户操作统计。用户进入终端后执行同名语句仍正常记录；历史无标记数据不靠文本猜测重写。

审计由 Agent 先持久化、上报并确认；失败时终止连接，不退回无审计透传。`cmd/audit-collector` 提供独立资产端证据投递入口，内置会话审计无需额外采集容器。

站内通知与业务状态在同一事务保存，分别投递给当前审批节点或申请人。SSE 接口 `GET /api/v1/events` 只发送分类信号，前端据此刷新对应查询，避免业务列表定时轮询。数据库提交触发通知，回滚不通知；每个 API 副本使用独立 PostgreSQL `LISTEN` 连接，不能使用事务池代理承载该连接。

SSE 连接每 20 秒保活。断线后退避重连，重连成功补刷持久化快照；权限变化或登录到期会关闭连接并重新鉴权。事件正文不携带业务明细，重新查询仍执行原有权限检查。

## API 与权限入口

业务接口前缀为 `/api/v1`。下表列出维护入口，完整路由见 [`server.go`](../internal/httpapi/server.go)，权限例外见 [`route_access.go`](../internal/httpapi/route_access.go)。

| 接口组 | 权限与额外约束 |
| --- | --- |
| `/auth/*` | 按登录、待验证 MFA 或当前账户区分；敏感动作强制加密 |
| `/regions`、`/assets/{id}/ports` | `directory:read`，只允许受控目录 |
| `/access-requests` | `request:manage`，限定申请人；创建要求幂等键 |
| `/approvals/*` | `approval:manage`，当前节点且禁止自批 |
| `/sessions/{id}`、`/terminal`、`/close` | `session:manage`，再校验所属申请和运行状态 |
| `/admin/sessions/{id}/force-close` | `session:override`，只授予回收能力 |
| `/session-records`、`/operation-audit-*` | 按申请人、审批参与人或审计权限限制记录范围 |
| `/audit-events` | `audit:read` |
| `/admin/assets`、云同步任务 | `catalog:manage`；凭据或证书管理可能另需 `role:manage` |
| `/admin/users`、`/admin/invitations` | `user:read` / `user:manage`；修改授权标签另需 `role:manage` |
| `/admin/roles`、`/admin/role-bindings`、`/admin/settings` | `role:manage` |
| `/admin/workflows`、`/admin/ownerships` | `workflow:manage` |
| `/notifications`、`/events` | 当前有效用户，服务端按接收者和业务权限过滤 |

`/healthz`、`/readyz` 为健康入口；`/metrics` 支持 Bearer token。飞书回调与内部审计接口使用各自的专用验证方式，不能当作匿名业务入口。旧 `/sessions/{id}/credential` 和 Token 领取接口已退出。

## 前端工程

技术栈为 React 18、TypeScript strict、Vite、Arco Design、原生 fetch、TanStack Query、Zustand 和 xterm.js。依赖方向固定为 `app → pages → features → shared`：

- `app` 管 Provider、路由、导航和布局；`pages` 编排页面。
- `features` 保存业务 DTO、API、query keys、Hooks 和业务组件，通过公开入口复用。
- `shared` 提供 API 客户端、传输加密、无业务语义的 UI 与通用工具，不反向导入业务层。
- 服务端数据由 TanStack Query 管理；Zustand 只保存界面偏好，身份与权限不重复写入 store。

浏览器传输实现位于 [`apps/web/src/shared/api/transport.mjs`](../apps/web/src/shared/api/transport.mjs)，由 API 客户端和终端首帧共用。Go 的 WebCrypto 互操作测试也引用同一实现，避免协议副本漂移。

统一使用 `PageHeader` / `PageBody`、`DataTable` / `OffsetPagination`、`ResourceForm`、`QueryState`、`CopyableText`、`PermissionGate` 等共享组件。列表为数组加 offset 分页，不虚构总数；写请求不自动重试；前端隐藏按钮不能替代后端权限检查。

### 辅助说明展示规范

- 字段含义、填写示例、配置依赖和操作背景使用 `HelpPopover` 的 `?` 入口，紧邻字段或操作，设置明确标题，保留可点击链接及键盘可访问性。
- 同一字段的说明集中在一个问号内，按当前选择展示；不使用常驻段落、`Form.Item extra/help` 或 `Alert` 堆放辅助说明。
- 实时错误、校验失败和阻塞状态直接展示。
- 审批预览固定为“提交申请 → 配置节点 → 审批结束”，只展示节点名称及箭头。资产表单通过“查看审批流程”弹窗展示；流程编辑页在表单下方实时预览。

生产构建由 Go 静态处理器提供。CSP 保持脚本及样式表同源，仅允许 Arco 必需的内联样式属性，不从 CDN 加载运行时资源。
