# access-gateway

按需申请、审批和回收的生产资产临时访问平台。

## 概览

access-gateway 把资产目录、访问审批、临时会话和审计放在同一个平台。用户申请指定资产、端口和有效期，审批通过后启动独立会话 Agent，到期或主动关闭时回收访问权限与连接。

本仓库包含 Go 控制平面、React 管理控制台、会话 Agent、数据库迁移和部署配置。网页、API 和后台任务共用一个服务；Docker 与 Kubernetes 下的会话 Agent 复用同一个业务镜像。

- **身份与授权**：本地账号、OIDC、LDAP、OAuth2、GitHub 和可选飞书登录，支持邮箱邀请、MFA、角色及标签授权。
- **审批与资产**：资产关联多级审批流程，支持负责人匹配、云资产导入、CMDB 同步及紧急申请。
- **临时访问**：默认使用站内终端；管理员可开启本地客户端访问。支持 SSH、MySQL、PostgreSQL、Redis、MongoDB 和 HTTP/HTTPS。
- **审计与回收**：记录连接、操作及终端输出，支持主动关闭、强制回收和绝对 TTL；单会话最长 5 小时。

## 使用

本地开发需要 Go 1.26+、Node.js 22.18+ 和 PostgreSQL 16+。先准备数据库，启动示例见[本地开发文档](docs/03-LocalDevelopment.md#启动数据库和应用)。

```bash
cp .env.example .env
# 在 .env 中设置 ENCRYPTION_KEY，并确认 DATABASE_URL、PUBLIC_URL。
# ENCRYPTION_KEY 可用 openssl rand -hex 32 生成，后续启动保留原值。
make dev
```

打开 `PUBLIC_URL`（默认 `http://127.0.0.1:9527`）。首次启动创建 `admin` 管理员，初始密码保存在 `var/dev-secrets/initial-admin-password`；再次启动不会重置账号。

生产镜像发布至 `kuzane/access-gateway`。Linux 部署使用 `docker-compose.yml` 与 `.env.example`；完整配置、HTTPS 入口和 Kubernetes 安装见[部署文档](docs/04-Deployment.md)。

## 文档

| 文档 | 内容 |
| --- | --- |
| [架构设计](docs/01-ArchitectureDesign.md) | 组件、访问链路、状态机、安全边界和数据恢复 |
| [模块实现](docs/02-ModuleImplementation.md) | 后端分层、身份授权、审批、会话、审计和前端约定 |
| [本地开发](docs/03-LocalDevelopment.md) | 环境准备、启动、调试、迁移及按范围验证 |
| [部署运维](docs/04-Deployment.md) | Docker、Nginx、Kubernetes、发布、备份和排障 |

## 构建

Go 工具链版本以 [go.mod](go.mod) 为准，前端依赖以锁文件为准。

```bash
make dev-install
make web-build
go build -o bin/access-gateway ./cmd/access-gateway
go build -o bin/gateway-agent ./cmd/gateway-agent

# 构建包含网页、控制平面、会话 Agent 和管理工具的统一镜像。
docker build --target access-gateway -t kuzane/access-gateway:local .
```

本地编译的控制平面通过 `WEB_ASSETS_DIR` 加载网页；生产镜像已配置好该目录。运行前先完成数据库迁移，详见[本地开发](docs/03-LocalDevelopment.md)。

## 问题反馈

通过 [Issues](https://github.com/srex-run/access-gateway/issues) 报告问题，附版本、部署方式、复现步骤和脱敏日志。请勿附账号密码、密钥或完整会话凭据。

## 参与开发

欢迎提交改进。修改前阅读[工程约束](agent.md)与对应模块说明，按改动范围执行验证，在变更说明中注明行为变化、验证结果和未覆盖的环境。
