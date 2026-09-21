# 本地开发

[项目首页](../README.md) · [架构设计](01-ArchitectureDesign.md) · [模块实现](02-ModuleImplementation.md) · [部署运维](04-Deployment.md)

## 环境准备

| 依赖 | 要求 |
| --- | --- |
| Go | 1.26+，精确工具链版本见 `go.mod` |
| Node.js | 22.18+，使用 npm 和已提交的 `package-lock.json` |
| PostgreSQL | 16+，为本项目创建独立数据库 |
| Docker | 仅使用可选开发数据库容器时需要 |
| 目标客户端 | 站内数据库/HTTP 终端需要 `mysql` 或 `mariadb`、`psql`、`redis-cli`、`mongosh`、`curl` 和 Bash |

SSH 终端由 Go 实现，不需要安装本机 SSH CLI。生产镜像已包含其他原生客户端；本地只需安装本次调试协议对应的客户端，并放入 `PATH`。macOS 使用系统 `sandbox-exec`；Linux 终端隔离条件见[部署环境](04-Deployment.md#部署前提)。

首次创建配置；已有 `.env` 时直接编辑，避免覆盖原密钥：

```bash
cp .env.example .env
openssl rand -hex 32
```

将生成值填入 `.env` 的 `ENCRYPTION_KEY`，确认以下配置：

```dotenv
DATABASE_URL=postgres://access_gateway:access_gateway@localhost:5432/access_gateway?sslmode=disable
ENCRYPTION_KEY=填写至少32字节的稳定密钥
PUBLIC_URL=http://127.0.0.1:9527
```

开发脚本默认监听 `127.0.0.1:8080`，使用 `local` 会话运行时；`ALLOW_DEV_AUTH` 默认关闭。需要调整时再添加对应覆盖变量。

`ENCRYPTION_KEY` 用于解密已有数据及派生用途密钥，不能在每次启动时重新生成。也可配置绝对路径的 `ENCRYPTION_KEY_FILE`，此时清空同名内联变量。`.env` 已排除在 Git 之外，敏感变量不得使用会暴露给浏览器的 `VITE_` 前缀。

## 启动数据库和应用

已有数据库时，填写 `DATABASE_URL` 后运行 `make dev`。没有现成 PostgreSQL 时，可先创建本地开发容器：

```bash
docker run -d --name access-gateway-dev-postgres \
  -e POSTGRES_DB=access_gateway \
  -e POSTGRES_USER=access_gateway \
  -e POSTGRES_PASSWORD=access_gateway \
  -p 127.0.0.1:5432:5432 \
  -v access-gateway-postgres:/var/lib/postgresql/data \
  postgres:16-alpine
```

用 `docker logs access-gateway-dev-postgres` 确认数据库已就绪，再运行 `make dev`。容器停止后使用 `docker start access-gateway-dev-postgres`，无需重新创建。若已有开发数据库容器，继续使用原容器及数据卷。

示例仅监听本机 `5432`，数据库、用户、密码均为 `access_gateway`，与模板中的 `DATABASE_URL` 一致，只适用于本地开发。调整这些值时同步修改 `DATABASE_URL`；已有数据卷不会因容器环境变量改变而重置凭据。

根目录 `docker-compose.yml` 用于 Linux 完整部署，说明见[部署文档](04-Deployment.md#docker-compose)。

开发与生产共用 [`.env.example`](../.env.example)。本地开发填写 `ENCRYPTION_KEY`、`PUBLIC_URL` 和 `DATABASE_URL` 即可，生产 Compose 专用的镜像、socket 组号和主机目录无需填写。

`make dev` 读取根目录 `.env`，已有进程环境变量优先，不把文件作为 shell 执行。启动顺序为：检查依赖 → 必要时 `npm ci` → 构建控制平面和 Agent → 应用新增迁移 → 首次初始化 → 启动后端与 Vite。任一步失败都停止后续启动。

打开 `PUBLIC_URL`。首次管理员默认是 `admin`，昵称为 `Administrator`：

```bash
cat var/dev-secrets/initial-admin-password
```

初始化由数据库 `installation_state` 记录；已有用户或完成记录时跳过，不重置密码或权限。首次账号可通过 `BOOTSTRAP_ADMIN_USERNAME`、`BOOTSTRAP_ADMIN_NICKNAME`、`BOOTSTRAP_ADMIN_PASSWORD_FILE` 配置。

前端修改由 Vite 热更新。Go 代码或 `.env` 修改后，Ctrl+C 停止并重新运行 `make dev`；Ctrl+C 或子进程失败会停止两个服务。保留 `var/session-agents`，供下次启动接管和回收会话。

## 演示模式

在 `.env` 中设置 `DEMO_MODE=true` 并重启应用，新访问申请将由系统自动审批通过并创建会话，有效期固定为 5 分钟，从自动审批通过开始计时，到期自动回收。管理员测试会话也固定为 5 分钟。申请页面会显示演示模式并锁定时长，审计记录保留“演示自动审批”标记。

默认值为 `false`。设回 `false` 并重启后，新申请恢复资产配置的审批流程，已有申请和会话继续按原状态及到期时间处理。演示模式仍校验申请权限、账号状态、资产、端口和访问配置；资产或平台最大时长不足 5 分钟时会拒绝创建，不会提高原有限制。升级已有环境需先执行新增迁移 `00037_demo_access.sql`；已有演示申请时，该迁移拒绝回滚，以保留真实的审批历史。

## 首次功能配置

1. 登录后修改管理员密码，在系统设置配置需要的认证源、SMTP 和 MFA；本地登录不依赖外部服务。
2. 创建区域、用户及角色。给审批人授予 `approval:manage`，配置审批流程；申请人与审批人使用不同账号。
3. 创建资产，填写真实目标地址、端口与协议，并关联有效审批流程。
4. 使用站内终端时启用端口操作审计，配置目标信任，保存“一键生成全部”的结果。目标服务需已经支持 TLS/SSH。
5. 提交申请，完成审批，在运行中的会话输入目标账号凭据连接；结束后查看访问轨迹及终端记录。

本地客户端访问默认关闭。需要测试时，在系统设置开启并填写可直达的客户端主机，在新申请中勾选客户端访问并填写实际来源 IP。详情页给出的会话端口与目标端口含义不同：客户端连接前者，Agent 连接后者。

## 常用命令

| 命令 | 用途 |
| --- | --- |
| `make dev-check` | 检查环境文件、端口配置和依赖状态，不连接数据库 |
| `make dev-install` | 按前端锁文件安装依赖 |
| `make dev-migrate` / `make dev-migrate-status` | 加载 `.env`，迁移或查看版本 |
| `make dev-init` | 只执行迁移与首次初始化 |
| `make dev-admin` | 手动创建管理员；不用于重复初始化已有账号 |
| `node scripts/dev.mjs --account reset-password --username admin` | 使用开发配置重置指定本地账号密码 |
| `make web-dev` | 单独启动 Vite，需要已有后端 |
| `make web-build` | 类型检查并构建到 `apps/web/dist` |
| `make run-web` | 构建前端，由 Go 同进程提供网页和 API |

`make run-web`、`make run` 与直接 `go run ./cmd/...` 不自动加载 `.env`。使用前先完成迁移和账户初始化，并向进程导出 `DATABASE_URL[_FILE]`、`ENCRYPTION_KEY[_FILE]`、`PUBLIC_URL` 等配置。静态网页由 `HTTP_ADDR` 提供，此时 `PUBLIC_URL` 应匹配实际访问的 Go 入口；日常前后端联调使用 `make dev` 即可。

本地 HTTP 开发中，`PUBLIC_URL` 的端口决定 Vite 监听端口；显式 `DEV_WEB_PORT` 与其冲突时拒绝启动。HTTPS 代理场景可单独设置 Vite 上游端口。`ACCESS_GATEWAY_UPSTREAM` 只控制 Vite 的 API 代理，代理已支持 WSS。

## 按改动范围验证

局部修改只运行直接相关流程。下面是可选入口，不是每次修改都要执行的清单：

```bash
# 例：原生连接身份校验。
go test ./internal/gateway -run '^TestNativeTCP' -count=1

# 例：开发配置解析。
node --test scripts/dev-config.test.mjs scripts/dev-dependencies.test.mjs

# 例：浏览器加密传输。
node --experimental-strip-types --test apps/web/tests/transport.test.mjs

# 生产 Compose 配置、凭据准备与重复启动；不启动容器。
node --test scripts/compose-startup.test.mjs

# 前端依赖边界、类型与构建按需使用。
npm --prefix apps/web run lint
npm --prefix apps/web run build
```

macOS 的临时目录可能经过 `/var` 或 `/tmp` 符号链接。校验私有目录的 Go 测试若因此失败，使用 `TMPDIR=/private/tmp go test <相关包>`，不放宽生产文件权限检查。

数据库改动使用真实 PostgreSQL 集成测试，不使用 SQL mock。`POSTGRES_TEST_DSN` 必须指向可丢弃的独立测试数据库，不能使用业务库；未设置时用例会跳过，不能视为验证通过：

```bash
POSTGRES_TEST_DSN='postgres://user:password@127.0.0.1:5432/access_gateway_test?sslmode=disable' \
  go test -tags=integration ./tests/integration -run '^Test目标用例$' -count=1
```

跨模块或发布验证可使用 `make lint`、`make test`、`make test-race`、`make test-integration`、`make web-check`。扩展验证前先明确变更风险和覆盖目标。

浏览器用例位于 `apps/web/tests/browser`，按文件选择 `npm --prefix apps/web run test:browser -- tests/browser/具体文件.spec.ts`。这些用例使用 API 替身；真实认证源、目标网络、SMTP 和端到端回收仍需在对应环境验收。

## 常见问题

| 现象 | 检查方式 |
| --- | --- |
| 写请求返回 `origin_mismatch` | 浏览器地址必须与 `PUBLIC_URL` 的协议、主机、端口完全一致 |
| 5432 或前端端口占用 | 调整开发数据库端口及 DSN，或停止冲突进程；API 与 Vite 端口需不同 |
| 数据库版本不足 | 停止服务后运行 `make dev` 或 `make dev-migrate`，确认连接到项目专用库 |
| 无审批流程或不能审批 | 检查资产关联流程、节点匹配、审批权限及是否自批 |
| 终端不能启动 | 检查目标审计配置、协议客户端是否在 PATH、系统沙箱能力 |
| TLS / SSH 身份校验失败 | 校验目标证书、名称、指纹或 SSH 主机公钥；不要关闭校验绕过 |
| 页面不实时更新 | 检查 `/api/v1/events` 长连接、PostgreSQL LISTEN 和代理缓冲 |

本地 Agent 日志位于 `var/session-agents/agents/<会话 ID>/agent.log`。使用 `failure_stage` 与 `reason` 区分客户端 TLS、目标 TLS、身份和审计失败；排障时保留待确认审计和会话状态目录。

## 脚本目录

根目录 `scripts/` 保留开发启动、部署操作和对应测试。入口与辅助模块的职责如下，Kubernetes 配置步骤见[部署文档](04-Deployment.md#kubernetes)。

| 文件 | 职责与调用入口 |
| --- | --- |
| `dev.mjs` | `make dev` 及迁移、初始化、账户管理命令；负责构建、启动和退出时回收进程 |
| `dev-config.mjs`、`dev-dependencies.mjs` | 开发入口内部模块；解析环境文件、校验端口及前端依赖安装状态 |
| `dev-config.test.mjs`、`dev-dependencies.test.mjs` | 上述配置和依赖检查的回归测试 |
| `compose-startup.test.mjs` | 验证默认 Compose 的依赖顺序、凭据准备和重复启动；不启动容器 |
| `render-production-manifests.sh`、`verify-production-manifests.sh` | CI 和 Kubernetes 部署使用的清单渲染与校验；不连接集群 |
| `public-url.sh`、`public-url.test.mjs` | 渲染器和生产预检共享的 HTTPS 来源解析及其测试 |
| `production-preflight.sh` | 检查已部署 Kubernetes 资源、运行时配置、权限和在线健康入口 |

## 运行数据

会话 Agent 的配置由控制面生成；目录发布逻辑由 `internal/catalogrelease` 的 Go 单元测试验证。

`var/` 是本地运行数据目录：`dev-secrets/` 保存首次管理员密码，`session-agents/` 保存会话配置、锁和恢复状态。整个目录已被 Git 与 Docker 构建上下文忽略；开发脚本和运行时会按需创建目录。
