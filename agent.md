# 项目级工程与数据访问约束

本文件是 `access-gateway` 项目的项目级开发约束。实现、评审和自动化代理都必须遵守本文件；不确定时先停下来询问，不要自行引入替代方案或放宽规则。

## 1. 项目技术栈

| 领域 | 约束/选型 |
| --- | --- |
| 语言 | Go |
| HTTP API | `go-restful` |
| 日志 | `zerolog`，结构化输出并统一脱敏 |
| 依赖组装 | `internal/app` 显式初始化，通过窄接口注入依赖 |
| 授权 | `gorbac`；资源和动作权限之外，业务状态必须由服务层显式校验 |
| 工作流 | `internal/approvalflow` 与 service 中的确定性审批、会话状态机 |
| Kubernetes | `client-go`，只用于受控的 Kubernetes 资源与网关运维集成 |
| 数据库 | PostgreSQL |
| 数据访问 | Go 标准库 `database/sql` + `github.com/jackc/pgx/v5/stdlib`（驱动名 `pgx`） |
| 迁移 | goose，文件放在 `migrations/` |

数据层不使用 ORM 或 query builder。Redis、任务队列、飞书、Vault/KMS 等外围依赖必须通过清晰的接口隔离，不得绕过服务层修改业务状态。

## 2. 依赖与分层

- 应用查询 SQL 只能出现在 `internal/repository/**`；迁移 DDL 是 `migrations/` 的明确例外。
- pgx 的 `database/sql` driver 只能在 `internal/db` 中 import，这是唯一的驱动注册点。若集中式 `mapError` 需要识别 `*pgconn.PgError`，只能为错误分类导入该类型，不得用它建立连接或绕过 `database/sql`。
- repository 方法接收窄接口 `DBTX`，接口只包含 `QueryContext`、`QueryRowContext`、`ExecContext`。方法不能接收具体的 `*sql.DB`。
- `*sql.DB` 和 `*sql.Tx` 都满足 `DBTX`，因此同一个 repository 方法必须既能直接调用，也能在事务中调用。
- 禁止引入任何 ORM 或 query builder：`gorm`、`xorm`、`ent`、`bun`、`sqlx`、`squirrel`、`goqu` 等均不可使用。
- 遇到复杂动态查询时按本文第 4 节处理，不得为了拼查询引入新库。
- 禁止 `pgxpool`。业务查询统一走 `database/sql`。`internal/realtime` 为 PostgreSQL `LISTEN/NOTIFY` 使用一条独立 pgx 连接，仅处理通知，不绕过 repository 查询业务数据。

推荐的职责方向：HTTP handler 负责协议适配，service 负责权限、状态机和事务边界，repository 负责固定 SQL 和显式映射，worker 负责异步任务编排，网关客户端负责受控的外部调用。

## 3. Scan 是数据层唯一的高危点

**`.Scan(` 只允许出现在 repository 的 `scan.go` 或 `*_scan.go` 中。** 其他任何文件出现即违规。

每个表必须在对应的 `scan.go` 中维护以下三个相邻的东西：

1. 列名常量 `xxxColumns`。
2. 扫描函数 `scanXxx(s RowScanner) (Xxx, error)`。
3. 注释声明列常量顺序与扫描参数顺序逐一对应。

规则：

- `Scan` 参数顺序必须与 `xxxColumns` 列顺序严格一致；每个参数后用行内注释标出对应列名。
- 改动列列表或 `Scan` 参数时，必须在同一次修改中同步另一处。
- 禁止在其他文件内联写 `rows.Scan(&a, &b, ...)`。
- 禁止 `SELECT *`。列顺序必须由代码显式控制，而不是依赖 schema 顺序。
- `RETURNING` 的列集合若与 `xxxColumns` 不同，必须单独定义列常量和扫描函数，不得复用。
- `jsonb` 先 Scan 到 `[]byte`，再使用 `json.Unmarshal`；不得依赖驱动直接解码到业务 struct。

列错位在类型兼容时可能既不编译失败也不返回驱动错误。因此任何列变更都必须同时更新扫描常量、扫描函数和覆盖每个字段的集成测试。

## 4. rows 循环

- 禁止手写 `for rows.Next()` 循环。
- 多行查询一律使用统一的泛型辅助函数 `CollectRows(rows, scanXxx)`；该函数负责 `defer rows.Close()`、遍历和最终 `rows.Err()` 检查。
- 单行查询使用 `QueryRowContext` + `scanXxx(row)`。
- 禁止把 `*sql.Rows` 返回到 repository 之外。

统一辅助函数的行为必须保持一致：关闭 rows、收集所有行、传播扫描错误，并在循环结束后检查 `rows.Err()`。不要在业务层重复实现这些步骤。

## 5. SQL 写法

- 占位符统一使用 `$1`, `$2`, ...；项目中不存在 `?` 占位符。
- IN 查询使用 `WHERE id = ANY($1)`，直接传 Go slice，由 pgx 编码为 PostgreSQL 数组；不要拼接可变数量占位符。
- **禁止 `LastInsertId()`**。PostgreSQL 不支持该 API；需要生成主键时使用 `INSERT ... RETURNING id` 和 `QueryRowContext`。
- 禁止 `fmt.Sprintf` 或字符串拼接参与 SQL 的值部分。
- 禁止持有长生命周期的 `Prepare` / `PrepareContext` statement。pgx 自带语句缓存，手动 prepare 会与连接池生命周期冲突。
- `UPDATE` / `DELETE` 必须检查 `RowsAffected()`。影响 0 行不是驱动错误，必须显式转换为 `ErrNotFound`。
- SQL 使用反引号原始字符串，在方法内部声明 `const query = ...`；列名部分引用 `xxxColumns` 常量。
- 所有 SQL 必须固定、可审计，并在 repository 方法中与操作名关联。

## 6. 动态查询

动态部分只能是标识符（列名、排序方向），且必须来自代码中的白名单 map。请求参数只能作为 map key，不能直接进入 SQL 文本。

分页统一使用 `LIMIT $n OFFSET $m`，页大小上限必须写入常量并在入口校验。

需要组合 WHERE 条件时，使用固定条件片段和参数序号递增；列集合必须来自已声明的 `xxxColumns` 常量，值始终通过 `$N` 参数传入。查询常量仍应在 repository 方法内部声明。不要引入 builder 库，也不要以字符串拼接方式拼接用户可控的值。

## 7. 类型映射

- 可空列必须 Scan 到指针（如 `*int64`、`*string`、`*time.Time`）或 `sql.NullX`；不可将 NULL 扫描到非指针基础类型。
- 时间列一律使用 `timestamptz` 并 Scan 到 `time.Time`。业务时间禁止使用无时区 `timestamp`。
- `numeric` 不得 Scan 到 `float64`。金额使用最小货币单位 `int64` 或明确的 decimal 类型。
- `jsonb` Scan 到 `[]byte` 后再 `json.Unmarshal`。
- 数组列 Scan 到对应 Go slice，由 pgx 负责编解码。
- UUID、枚举和状态值必须在边界处校验；不要把任意字符串直接当作合法状态流转。

## 8. 错误处理

- `sql.ErrNoRows` 必须转换为包级 `ErrNotFound`。不允许裸抛，也不允许把它吞掉当作空值。
- PostgreSQL SQLSTATE 统一映射，集中在一个 `mapError` 函数中，并使用 `errors.As` 获取 `*pgconn.PgError`：
  - `23505`（unique violation）-> `ErrConflict`
  - `23503` / `23514`（foreign key / check）-> `ErrConstraint`
- 所有返回的 error 都必须使用 `%w` 包装并带上操作名，例如 `fmt.Errorf("create session: %w", err)`。
- repository 中禁止 `context.Background()` 和 `context.TODO()`；必须使用调用方传入的 ctx。
- 不要把数据库驱动错误、SQL 文本或 Token 明文直接返回给 HTTP 客户端。

`mapError` 是数据层唯一的 SQLSTATE 归一化入口。新增数据库错误映射时同步更新测试和调用方的错误语义。

## 9. 事务

- 事务边界只在 service 层，通过 `InTx(ctx, func(q DBTX) error { ... })` 管理。
- repository 方法签名固定为 `(ctx context.Context, q DBTX, ...)`，方法内部禁止 `BeginTx`。
- `InTx` 必须在 `defer` 中处理 rollback，并覆盖 panic 路径。
- commit 之后 defer 中的 rollback 若返回 `sql.ErrTxDone`，必须显式忽略。
- 事务内禁止 HTTP 调用、飞书调用、网关调用或长耗时计算；外部调用使用 outbox/任务队列做可靠投递。
- 状态机更新、会话事件和 outbox 事件需要在同一个本地事务中写入，以保证可恢复性。

## 10. Schema 与 migration

- migration 工具使用 goose，文件在 `migrations/`。
- **已提交的 migration 文件不可修改，只能新增版本。**
- 改列名或删列必须分两阶段：先加新列并双写，再迁移数据，后续版本才可删除旧列；禁止一个版本直接 `DROP COLUMN`。
- 任何列变更必须在同一个变更中同步更新 `scan.go` 的列常量和扫描函数。
- 应用代码禁止执行任何 DDL。
- 新增查询必须在 PR/变更说明中附 `EXPLAIN (ANALYZE, BUFFERS)` 结果，并说明命中的索引。出现 Seq Scan 时解释原因和可接受性。
- schema 中业务时间使用 `timestamptz`；敏感目标映射使用加密字段，不保存明文凭证。

## 11. 连接池

- 池配置集中在一个 `Config` 结构中，默认值未经明确要求不得改动。
- `ConnMaxLifetime` 必须设置。云 RDS 和 L4 负载均衡可能静默断开连接，不设置 lifetime 会把坏连接交给业务。
- `MaxIdleConns` 与 `MaxOpenConns` 保持相等，避免 idle 小于 open 导致连接反复建立和销毁。
- 如果部署在 PgBouncer transaction pooling 之后，必须关闭语句缓存：`DefaultQueryExecMode = pgx.QueryExecModeExec`，两个 cache capacity 归零。该开关只能在目标环境验证后调整，不得凭猜测修改。
- 每个连接池必须使用可取消的 context，并在启动时执行健康检查。

## 12. 测试与交付门槛

- 每个 repository 方法必须有真实 PostgreSQL 测试（testcontainers 或 docker-compose 启动一次性实例）。
- 不接受 sqlmock。它只能匹配 SQL 字符串，无法覆盖 Scan 错位、类型不匹配和占位符数量错误等高风险问题。
- 新增或修改 `scan.go` 时，测试必须断言每个字段的值，不能只断言 `err == nil`。
- 测试必须覆盖：空结果到 `ErrNotFound`、唯一约束、外键/check 约束、NULL 字段、分页边界、事务回滚、重复幂等键和状态条件更新。
- 按变更范围运行最小相关验证：文档检查链接，配置检查解析，局部代码运行对应文件、包或用例。小任务不默认执行全量测试或全仓扫描。
- 涉及跨模块合同、发布或安全关键路径，或最小验证不足时，先说明原因再扩大范围。完整入口包括 `make lint`、`make test` 和 `make test-integration`，并非每次修改的必选项。

只交代码不跑测试不算完成。若本地没有 Docker/PostgreSQL，必须在交付说明中明确记录未执行的集成测试，而不是用 sqlmock 替代。

## 13. 数据层自查清单

每次修改数据层代码后逐条确认：

- [ ] `.Scan(` 只在 repository 的 `scan.go` 或 `*_scan.go`；列常量与 Scan 顺序逐一对应，并有行内列名注释
- [ ] 没有 `SELECT *`
- [ ] 没有手写 `rows.Next()` 循环
- [ ] 占位符全是 `$N`；IN 使用 `= ANY($1)`
- [ ] 没有 `LastInsertId`；自增/生成主键走 `RETURNING`
- [ ] `UPDATE` / `DELETE` 检查了 `RowsAffected`
- [ ] nullable 列 Scan 到指针或 `sql.NullX`
- [ ] `sql.ErrNoRows` 已转成 `ErrNotFound`
- [ ] 方法签名是 `(ctx, q DBTX, ...)`，没有内部开事务
- [ ] 没有新增第三方数据层依赖
- [ ] 集成测试已本地跑通，并断言了所有字段值
- [ ] 新查询附带 `EXPLAIN (ANALYZE, BUFFERS)` 证据

## 14. 生产访问领域红线

数据层规则之外，所有实现还必须遵守[架构设计](docs/01-ArchitectureDesign.md#安全边界)：资产和端口只能来自受控目录；浏览器敏感信息使用一次性加密挑战，目标凭据不写入日志、URL 或持久化授权；网关必须独立执行绝对 TTL；控制平面不能把用户输入拼成命令；审批人不能自批；回收失败必须告警并支持人工强制终止。当前会话只创建原生加密或审计模式，不恢复旧隧道协议。
