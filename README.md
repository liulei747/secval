# Secval

## 架构与后续实施

- [审计架构与实施基线](docs/audit-architecture-plan.md)：参考Codex Security的方法、目标流程、现状、阶段验收与决策记录。
- [当前只读审计原型](docs/audit-agent.md)：已实现接口、配置和限制。

后续审计功能开发先核对上述文档。目标为独立Web审计应用，当前原型不等于完整审计系统。

## 使用远程 Embedding API

搜索服务默认继续使用本地 `Qwen/Qwen3-Embedding-0.6B`。如果要改用 OpenAI
兼容的 Embedding API，把 `.env.example` 复制为 `.env`，填写完整的
`SECVAL_EMBEDDING_API_URL` 和 `SECVAL_EMBEDDING_API_KEY`，然后重新构建并启动
API 容器。默认远程模型 ID 是 `qwen3.7-text-embedding`。
API 地址既可以填写 `/v1` 基础地址，也可以填写完整的 `/v1/embeddings`。

远程模型使用独立的 Qdrant Collection。切换模型后必须重新建立仓库索引，查询
和代码入库必须使用同一个模型及维度；接口返回维度不是 1024 时，服务会拒绝写入
并报告实际维度，随后再据实调整配置。

Secval 是一个面向代码分析的大型 Web 平台。

当前首先建设混合搜索板块。搜索板块会把关键词搜索和向量搜索的结果合并，向后续的代码关系、代码路径和 Agent 板块提供代码片段。

Docker搜索链路还会使用本地 `BAAI/bge-reranker-base` CrossEncoder 对RRF排在
前面的10个候选做精排。模型只在API进程启动时加载一次；如果推理失败，搜索会自动
退回RRF结果，不会导致整个搜索请求失败。相关参数位于 `config/search.docker.yaml`
的 `reranker` 节，本地非Docker配置默认关闭该功能。

## 当前目录

- `web_api`：接收HTTP请求并把结果转换成响应，不实现搜索算法。
- `services`：编排建库和搜索流程；`SearchService`只调用能力接口。
- `models`：代码仓库、代码块、符号、搜索条件和搜索结果等核心数据对象。
- `interfaces`：定义Embedding、关键词召回、向量召回、结果融合和重排序能力。
- `infrastructure`：使用OpenSearch、Qdrant、Embedding模型、RRF和CrossEncoder实现上述能力。
- `bootstrap`：读取配置、创建连接和模型，并把具体实现注入业务服务。
- `code_processing`：扫描、解析、切分源代码以及生成可索引代码块。
- `config`：各模块的配置数据类型、读取和校验代码。
- `models/identifiers`：仓库、版本、文件、代码块和符号的强类型ID及生成规则。

正式搜索依赖方向固定为：

```text
web_api → services → interfaces → models
              ↑
bootstrap → infrastructure
```

`bootstrap`负责把基础设施实现注入`services`。例如，搜索服务只认识
`KeywordRetriever`、`VectorRetriever`、`ResultFusion`和`Reranker`，不会直接
创建OpenSearch、Qdrant或CrossEncoder对象。

当前已接入 Neo4j 声明关系、Joern 调用/数据流路径和多 Agent 审计。
MCP 按当前范围暂不实现。图与路径结果只是定位线索，必须回到固定源码快照核实后才能作为审计证据。

## 本地服务

本地服务由根目录的 `compose.yaml` 管理，Compose 项目名称是 `secval`。

当前服务：

- `secval-api`：FastAPI 搜索接口，仅监听本机 `127.0.0.1:8000`。
- `secval-opensearch`：单节点 OpenSearch，仅监听本机 `127.0.0.1:9200`。
- `secval-qdrant`：Qdrant 向量数据库，仅监听本机 `127.0.0.1:6333` 和 `127.0.0.1:6334`。
- `secval-neo4j`：代码声明关系图，管理页和 Bolt 端口仅监听本机。
- `secval-joern`：代码调用和静态数据流分析，只在 Compose 内部网络提供服务。

启动：

```powershell
docker compose up -d --build
```

首次启动 API 会下载 Qwen Embedding 模型，完成时间取决于网络。模型保存在
Docker 的 `huggingface-cache` volume 中，后续重启会复用缓存。

健康检查：

```powershell
Invoke-RestMethod http://127.0.0.1:8000/api/health
```

API 文档：<http://127.0.0.1:8000/docs>

### 导入代码仓库

Web 客户端先通过 `POST /api/repositories/upload` 上传代码目录。这个接口使用
`multipart/form-data`，包含以下字段：

- `repository_directory`：服务端保存使用的目录名；
- `replace_existing`：是否明确允许替换已有同名目录，默认为 `false`；
- `files`：一个或多个代码文件，文件名中保留仓库内的相对路径。

上传成功后会返回 `repository_path`。再把这个值交给建库接口：

也可以通过 `POST /api/repositories/upload-zip` 上传单个 ZIP。字段为
`repository_directory`、`replace_existing` 和 `zip_file`。服务端会检查解压路径、
文件数量、解压总大小、加密条目和符号链接，并自动去掉唯一的最外层目录。

```powershell
$body = @{
    repository_id = "example-project"
    repository_name = "Example Project"
    repository_path = "example-project"
    snapshot_id = "example-project-main"
    version = "main"
} | ConvertTo-Json

Invoke-RestMethod `
    -Method Post `
    -Uri http://127.0.0.1:8000/api/repositories/index-jobs `
    -ContentType application/json `
    -Body $body
```

后台接口立即返回任务编号，使用
`GET /api/repositories/index-jobs/{job_id}` 查看状态。服务重启时，未完成任务会标记为
`interrupted`；需要用户明确调用 `POST /api/repositories/index-jobs/{job_id}/resume`
创建续跑子任务。同步 `/api/repositories/index` 仅为兼容旧客户端保留。

`POST /api/repositories/index-jobs/{job_id}/cancel` 请求在下一个安全阶段停止。
进入“绑定新索引与源码”或“清理旧索引”后会返回 409，避免半提交。已取消任务可以通过
同一个 `/resume` 接口建立新的子任务，原任务记录不会被覆盖。

新任务会返回 `created_at`、`started_at`、`finished_at` 和 `stage_history`。如果失败，
`failed_stage` 保存失败前正在执行的阶段。时间使用 UTC ISO 8601 格式，浏览器测试页面
会换算成本地时间。历史任务没有真实时间时字段为空，不会用数据库升级时间代替。

运行中的任务还会返回 `worker_id`、`heartbeat_at`、`lease_expires_at` 和 `attempt`。
工作线程在长步骤中持续续租，任务结束后清空到期时间。租约当前用于证明哪个进程负责任务
以及识别失联，不会自动抢占或重跑过期任务；恢复仍需用户明确调用 `/resume`。

租约状态包括 `pending`（等待认领）、`healthy`（正常续租）、`expired`（心跳过期）、
`inactive`（任务已结束）和 `missing`（旧运行记录没有租约）。只有 `expired` 才能调用
`POST /api/repositories/index-jobs/{job_id}/recover-stale`；服务还会确认操作系统进程锁无人
持有，然后仅把任务收口为 `interrupted`。该接口不执行索引，后续仍需显式 `/resume`。
非法时间会显示为 `invalid` 并拒绝恢复，不会把损坏数据误判为失联。

`repository_path` 必须是 `data/repositories` 下的相对路径。API 会拒绝绝对路径和
越过挂载根目录的路径。同一主机上的多个 API 进程也会通过文件锁串行导入，失败批次会回滚。
上传接口先写临时目录，全部文件保存成功后才替换正式目录；默认不会覆盖已有仓库。

### 搜索

`GET /api/repositories`返回当前OpenSearch文本索引中实际存在的仓库/快照组合，
以及各组合的`chunk_count`。列表不把仅上传未建索引的目录当成可查询仓库，
也不表示当前Embedding API或向量索引一定可用。
测试前端的搜索区可以刷新并选择这些组合，搜索范围不再读取左侧入库表单的默认值。

```powershell
$body = @{
    text = "find user"
    repository_ids = @("example-project")
    snapshot_ids = @("example-project-main")
    top_k = 10
} | ConvertTo-Json

Invoke-RestMethod `
    -Method Post `
    -Uri http://127.0.0.1:8000/api/search `
    -ContentType application/json `
    -Body $body
```

代码标识符的大小写、下划线和数字拆分由 OpenSearch 的 `code_analyzer` 完成。

当前支持 Java 和 Python。Java 会建立以下可搜索代码块：

- 文件头（包声明、导入和文件级注释）；
- 类、接口、枚举、注解类型、记录类型和模块；
- 方法、构造函数、字段、记录组件、枚举常量和注解元素；
- 静态初始化块、实例初始化块和匿名类。

类型代码块只保存声明头，方法和构造函数保存完整实现，避免把同一份方法体同时塞进
整类和整文件代码块。多字段声明只保存一个代码块，但会关联其中的全部字段符号。
import、参数、局部变量、Lambda 和注解的“使用位置”不会单独建符号，它们仍然保留在
所属声明的正文中并可被全文搜索。没有文件头的默认包文件会复用首个类型声明头建立
`file` 块；没有归入声明正文的独立尾部或间隔注释也会保留为 `file` 块。

Python 当前建立文件头、类、函数、异步函数和方法块，装饰器会跟随对应声明。
Java/Python 混合仓库的搜索入库已支持。Joern 会按语言建立独立子项目并合并查询结果；
这可以保留各语言内部的调用和数据流，但不代表已建立 Java 与 Python 之间的跨语言调用边。

查看状态：

```powershell
docker compose ps
```

停止服务但保留索引数据：

```powershell
docker compose down
```

本地开发暂时关闭了 OpenSearch Security 插件。这个配置不能直接用于生产环境，也不能把端口改成公网监听后继续使用。
