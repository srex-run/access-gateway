# 部署运维

[项目首页](../README.md) · [架构设计](01-ArchitectureDesign.md) · [模块实现](02-ModuleImplementation.md) · [本地开发](03-LocalDevelopment.md)

## 部署文件

| 文件或目录 | 用途 |
| --- | --- |
| [`docker-compose.yml`](../docker-compose.yml) | Linux 应用、PostgreSQL、配置准备、迁移和首次初始化 |
| [`deploy/nginx`](../deploy/nginx) | 同机 HTTPS、WebSocket 和 SSE 入口 |
| [`deploy/kubernetes`](../deploy/kubernetes) | Kubernetes 基础资源、迁移 Job 和会话运行时 RBAC |
| [`deploy/overlays/production`](../deploy/overlays/production) | 固定镜像 digest、Ingress 和生产网络策略 |
| [`deploy/observability`](../deploy/observability) | Prometheus 监控、告警和 Grafana 面板 |
| [`deploy/external-secrets`](../deploy/external-secrets)、[`deploy/csi`](../deploy/csi) | 外部密钥系统接入示例 |
| [`deploy/postgresql`](../deploy/postgresql) | 可选 CloudNativePG 高可用与备份示例 |

生产按 Compose 或 Kubernetes 选择一条部署路径。会话 Agent 由控制面按授权启动，配置通过会话文件传入，不需要单独的环境变量模板或常驻 Agent 服务。

## 部署前提

- PostgreSQL 16+，使用项目独立数据库，明确备份和恢复方案。实时更新需要持久的 PostgreSQL LISTEN 连接，不能让该连接经过事务池模式代理。
- 一个稳定的 HTTPS `PUBLIC_URL`，只包含协议、主机和可选端口，不含路径、查询参数或片段。网页与 API 同源。
- 控制平面、Agent 能访问获批目标及必要外部认证源；目标服务已启用 SSH 或 TLS。按实际资产端口限制网络出口。
- Docker 生产部署使用 Linux 和 Compose v2。该部署使用 host 网络，不适用于 Docker Desktop 的生产环境。
- 站内原生客户端需要 Linux 5.13+、Landlock、seccomp 用户通知与文件描述符注入能力，推荐受支持的 6.x 内核。缺少能力时终端拒绝启动，不降级为无隔离运行。

只需要站内终端时，用户只需访问网站 HTTPS/WSS。本地客户端访问默认关闭，启用步骤见下文，不必预先向用户开放整个会话端口池。

## 镜像与发布

统一业务镜像包含网页、控制平面、会话 Agent、数据库迁移、本地账户及辅助工具；PostgreSQL 与 Nginx 使用各自镜像。

```bash
docker build --target access-gateway -t kuzane/access-gateway:local .
```

[`release.yml`](../.github/workflows/release.yml) 在推送 `v*` tag 后发布 amd64/arm64 镜像，生成签名、构建证明和 digest 附件。仓库 Actions 需配置 `DOCKERHUB_USERNAME`、`DOCKERHUB_TOKEN`。生产将 `ACCESS_GATEWAY_IMAGE` 设为 Release 对应的 `kuzane/access-gateway@sha256:...`，控制平面与动态 Agent 使用同一镜像。

本机源码构建得到的 `kuzane/access-gateway:local` 可用于验证，但不代替已发布的不可变生产镜像。基础镜像也应按组织的更新策略锁定与维护。

## Docker Compose

### 首次安装

在仓库根目录操作；已有配置时编辑原 `.env`，不要覆盖已有凭据。

```bash
cp .env.example .env
openssl rand -hex 32
stat -Lc '%g' /var/run/docker.sock
```

填写以下配置：

| 配置 | 说明 |
| --- | --- |
| `ACCESS_GATEWAY_IMAGE` | 已拉取或可拉取的统一业务镜像，生产使用 digest |
| `PUBLIC_URL` | 用户实际访问的 HTTPS 来源 |
| `POSTGRES_PASSWORD` | 首次部署设置强密码；已有数据库沿用原密码 |
| `ENCRYPTION_KEY` | 至少 32 字节，首次生成后固定并备份 |
| `ACCESS_GATEWAY_SECRETS_HOST_PATH` | 主机凭据目录，默认模板为 `/secure/control-secrets` |
| `SESSION_AGENT_STATE_HOST_PATH` | 主机会话状态目录，默认模板为 `/srv/access-gateway/sessions` |
| `DOCKER_SOCKET_GID` | 上一条 `stat` 命令的数字结果 |
| `POSTGRES_DATA_HOST_PATH` | 默认 `./data/postgres`，相对于 Compose 文件所在目录 |
| `POSTGRES_NETWORK_PREFIX` | 默认 `172.29.0`，对应私有 `/24` 网段，避免与现有路由重叠 |

```bash
docker compose config --quiet
docker compose up -d access-gateway
docker compose ps -a
docker compose logs --tail=100 prepare postgres migrate initialize access-gateway
```

启动依赖为 `prepare → postgres 健康 → migrate → initialize → access-gateway`。`prepare` 创建私有凭据及状态目录；内置数据库连接字符串按数据库配置生成，特殊字符会编码。已有密钥文件会复用，配置与持久化值不一致时停止启动。

首次管理员默认是 `admin`；以模板目录为例，使用 `sudo cat /secure/control-secrets/initial-admin-password` 查看初始密码，登录后修改。自定义目录时替换路径。初始化完成后重启、升级不会重置密码或权限。

内置数据库在 Docker 内部网络使用 `postgres:5432`，不发布主机端口。主应用使用 host 网络和名称映射访问数据库，HTTP 默认仅监听 `127.0.0.1:8080`，由 HTTPS 代理提供外部入口。状态目录与 Docker socket 仅供控制平面管理会话；会话容器不挂载主机 Docker socket。

开发与生产共用根目录的 [`.env.example`](../.env.example)。生产需要将 `PUBLIC_URL` 改为实际 HTTPS 地址，并填写上表必填项。模板中的 `DATABASE_URL` 仅供本地开发使用；生产 Compose 固定使用内置 PostgreSQL，连接字符串由 `prepare` 写入凭据文件。应用运行时的 `GATEWAY_RUNTIME=docker`、监听地址、Agent 镜像与路径由 Compose 统一设置，无需重复配置。Kubernetes 按下文的 Secret 配置数据库连接。

### 数据目录与权限

应用使用 UID/GID `65532`。凭据为私有普通文件，不能经过符号链接，不允许 group write 或 other access；同时设置 `NAME` 与 `NAME_FILE` 会报错。Compose 已处理运行时文件路径，通常无需手工创建各个 Secret 文件。

Docker socket 权限不足时检查 `DOCKER_SOCKET_GID` 与主机实际组号，更改后重新创建应用容器。不要通过将 socket 改成全员可写解决权限问题。

若旧安装使用 PostgreSQL 命名卷，切换到 `data/postgres` 前先停止业务写入并备份，用 `pg_dump`/恢复流程迁移至新目录，或在停止 PostgreSQL 且版本一致时迁移其完整数据目录。完成验证前保留旧卷。数据库名、用户名和密码环境变量只初始化空目录，不能修改已有数据库的登录密码。

## Nginx HTTPS 入口

[`deploy/nginx/conf.d/access-gateway.conf`](../deploy/nginx/conf.d/access-gateway.conf) 默认转发同机 `127.0.0.1:8080`。先将 `server_name` 改为 `PUBLIC_URL` 的域名，在 `deploy/nginx/tls/` 放入证书链与私钥，并按实际文件名修改 `ssl_certificate` 与 `ssl_certificate_key`。示例文件名不是已提供的证书。

```bash
docker compose -f deploy/nginx/docker-compose.yml run --rm nginx nginx -t
docker compose -f deploy/nginx/docker-compose.yml up -d
```

修改配置后使用 `docker compose -f deploy/nginx/docker-compose.yml exec nginx nginx -t` 校验，再运行同一前缀的 `exec nginx nginx -s reload`。

代理必须保留 Host 与外部协议，支持 HTTP/1.1 Upgrade/Connection，并关闭响应缓冲。模板的 75 秒读写超时可配合 SSE 20 秒保活和终端长连接。证书应覆盖网站域名并被客户端信任；仅用于 CDN 到源站的证书不能直接作为普通浏览器的受信证书。

## 启用本地客户端访问

1. 在系统设置启用客户端访问，填写用户可直达的主机 IP 或域名；不填写协议、端口或路径。
2. local/Docker 放行配置的 `SESSION_AGENT_PORT_START` 到 `SESSION_AGENT_PORT_END`（默认 `20000–20999`）；Kubernetes 使用实际 NodePort 范围及对应四层入口。
3. 新申请勾选客户端访问，填写 Agent 实际看到的来源 IP。网页入口仍按登录身份授权。
4. 使用会话详情给出的主机、会话端口、目标账号及信任文件连接；数据库启用 TLS，SSH 校验主机密钥。

网站域名可以经过普通 HTTPS/CDN 代理，但数据库与 SSH 会话端口需要直达或专用四层代理。关闭系统开关只影响新授权；要立即断开已有授权，在会话管理中结束对应会话。更换客户端主机后，应更新相关证书并重新申请。

## Kubernetes

基础清单为两副本控制平面、Service、PDB、RBAC、网络策略和独立迁移 Job。会话 Agent 按需创建 Pod；只在授权启用本地客户端时创建 NodePort。Agent 的 `8090` 管理入口使用会话独立 mTLS，`8091` 用于就绪检查，用户不直接访问管理端口。

生产需要 Ingress Controller、有效 TLS、支持所需策略的 CNI，以及生产 overlay 引用的 Prometheus Operator CRD。`deploy/kubernetes` 与生产 overlay 的占位值不能直接上线。

### 凭据与配置

使用受控 Secret、External Secrets 或 CSI 创建 `access-gateway-secrets`，不要直接应用 `secrets.example.yaml` 的占位内容。当前基础清单使用：

| Secret key | 用途 |
| --- | --- |
| `database-url` | PostgreSQL DSN |
| `encryption-key` | 平台稳定主密钥 |
| `metrics-bearer-token` | Prometheus 抓取凭据 |
| `audit-collector-secret` | 资产端独立采集接口凭据 |
| `asset-encryption-key` | 基础清单选择的独立资产密钥，需配套版本 ID |
| `cmdb-bearer-token` | 仅启用 CMDB 时使用 |

Secret 投影由 init 容器复制到内存卷，提供给应用的文件权限为 `0400`。使用 CSI 时保持 key 名与挂载合同一致。应用启动时读取 Secret，更新后需安排 rollout。使用独立资产密钥的已有安装必须保留原值和 key ID。

生产渲染脚本要求导出以下环境变量，参数含义及格式由脚本校验：

| 参数组 | 环境变量 |
| --- | --- |
| 固定镜像 | `ACCESS_GATEWAY_IMAGE_DIGEST`、`BUSYBOX_IMAGE_DIGEST` |
| 网站与监控 | `PUBLIC_URL`、`INGRESS_TLS_SECRET`、`INGRESS_NAMESPACE`、`MONITORING_NAMESPACE` |
| 数据库网络 | `POSTGRES_CIDR`、`POSTGRES_PORT` |
| 资产与客户端 | `TARGET_CIDR`、`ACCESS_SOURCE_CIDR` |
| Kubernetes API | `KUBERNETES_API_CIDR`、`KUBERNETES_API_PORT` |
| 外部 HTTPS 服务 | `EXTERNAL_HTTPS_CIDR` |
| 会话与身份 | `SESSION_AGENT_NODE_NAME`、`ASSET_KEY_VERSION`、`ADMIN_USER_IDS` |

`SESSION_AGENT_NODE_NAME` 是实际承载会话的节点；`ADMIN_USER_IDS` 是启动管理员的身份 ID 配置，不是账号密码，也不代替本地账号创建。检查 CIDR 与 CNI 实际看到的源/目的地址，禁止用户绕过网关直连目标。

```bash
# 配置上述环境变量后渲染并自动验证生产清单。
scripts/render-production-manifests.sh > /tmp/access-gateway-production.yaml
```

渲染器调用 `verify-production-manifests.sh` 检查固定 digest、占位值及所需资源。基础模板可通过 `kubectl kustomize deploy/kubernetes` 本地查看。

### 部署顺序

1. 准备命名空间、数据库、受控 Secret、ConfigMap、RBAC 和网络前提。
2. 从本次渲染结果部署 `access-gateway-migrate` Job，等待完成。升级时需重新创建该 Job；重复 apply 已完成的旧 Job 不会执行新迁移。
3. 迁移成功后应用本次渲染的 Deployment 及其余资源，等待 rollout。迁移失败时停止发布。
4. 首次安装使用镜像中的 `account` 工具创建本地管理员；已有安装跳过。完整 Compose 的自动初始化依赖不适用于 Kubernetes 模板。

```bash
kubectl -n access-gateway wait --for=condition=complete job/access-gateway-migrate --timeout=600s
# 确认前述迁移成功后，再应用完整渲染文件。
kubectl apply -f /tmp/access-gateway-production.yaml
kubectl -n access-gateway rollout status deployment/access-gateway --timeout=2m

# 仅首次安装，交互输入密码。
kubectl -n access-gateway exec -it deployment/access-gateway -- \
  /usr/local/bin/account create --username admin --nickname Administrator --admin
```

生产预检使用 `PUBLIC_URL=https://实际域名 scripts/production-preflight.sh`，会读取目标集群资源和验证在线入口。

## 升级、回滚与备份

升级前备份 PostgreSQL、原 `ENCRYPTION_KEY`、独立资产密钥及其版本、部署配置和必要的会话状态。密钥丢失无法仅靠数据库恢复资产地址、云凭据和系统设置。旧变量 `MASTER_KEY[_FILE]` 升级为 `ENCRYPTION_KEY[_FILE]` 时保持同一个值，不能重新生成。

旧 `tunnel` / `direct` 会话及客户端凭据接口已经退出，升级前结束这些旧会话；升级后重新申请，不能把旧授权自动转换成当前协议。历史数据库迁移与审计数据继续保留。

常驻 Agent 启动入口与 `GATEWAY_RUNTIME=http` 已移除。原来使用该模式的部署需切换为 `local`、`docker` 或 `kubernetes`，由控制面生成会话配置并启动 Agent。

Compose 更新镜像引用后，使用原 `.env`、凭据目录、数据库目录和状态目录运行同一条 `up -d access-gateway`。它会按依赖执行迁移和初始化检查。控制平面与会话镜像一起更新；当前运行会话的处理需按发布窗口安排。

```bash
docker compose run --rm migrate status
docker compose up -d access-gateway
```

历史迁移不可改写，应用不自动降级 schema。回滚前确认前一镜像能使用当前数据库结构；备份恢复需在独立环境验证账号、资产解密、审计查询和会话回收。不删除待确认审计或运行中的会话状态来“修复”启动。

## 监控与排障

| 现象或告警 | 处置重点 |
| --- | --- |
| `/readyz` 失败、应用未启动 | 数据库连通、迁移版本、原密钥、Secret 文件权限、实时监听初始化 |
| PostgreSQL 健康检查失败 | 持久化密码与实际角色密码是否一致，不能只看 `pg_isready` |
| `origin_mismatch` | 浏览器 URL、`PUBLIC_URL`、代理 Host/协议是否一致 |
| Agent 无法启动 | Docker socket GID、状态目录、镜像；Kubernetes 则检查 RBAC、节点、调度和网络策略 |
| `source_ip_mismatch` | 检查客户端出口或 NAT 后来源 IP，与申请值一致 |
| 目标证书或 SSH 身份错误 | 检查目标信任材料和名称；目标更换身份后重新配置 |
| `operation_audit_unavailable`、审计积压 | 检查控制平面可达性、会话凭据、状态存储与投递确认，保留未确认记录 |
| TTL 后仍有会话、`manual_intervention` | 核对实际 Agent/端口并执行强制回收，修复失败原因后确认状态与审计 |
| outbox 积压、数据库等待增加 | 检查任务错误、租约、数据库连接池、慢查询及外部依赖 |
| SSE 或终端频繁断开 | 检查代理缓冲、Upgrade、超时、LISTEN 连接及登录/会话有效期 |

Prometheus 使用 `metrics-bearer-token` 抓取 `/metrics`，告警及面板在 `deploy/observability`；OpenTelemetry 可通过 `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` 配置。避免向公网公开完整指标或泄露敏感日志。

首次上线至少验证一条真实目标的“申请 → 审批 → 连接 → 审计 → 关闭/到期”链路，以及来源限制、权限隔离、拒绝自批、控制平面重启和审计失败行为。启用的 SMTP、OIDC、LDAP、OAuth2、GitHub、飞书、云 API 应分别验证真实环境；模拟测试通过不能替代这些验收。
