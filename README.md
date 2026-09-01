# Secval

Secval 是一个面向代码分析的大型 Web 平台。

当前首先建设混合搜索板块。搜索板块会把关键词搜索和向量搜索的结果合并，向后续的代码关系、代码路径和 Agent 板块提供代码片段。

## 当前目录

- `shared_config`：全项目共享配置。
- `shared_types`：多个板块共同使用的数据类型和资源 ID。
- `code_processing`：扫描、解析和切分源代码。
- `hybrid_search`：建立索引并执行混合搜索。
- `web_api`：向 Web 前端或其他服务提供 HTTP 接口。

Neo4j、Joern、Agent 和 MCP 暂未创建。

## 本地服务

本地服务由根目录的 `compose.yaml` 管理，Compose 项目名称是 `secval`。

当前服务：

- `secval-api`：FastAPI 搜索接口，仅监听本机 `127.0.0.1:8000`。
- `secval-opensearch`：单节点 OpenSearch，仅监听本机 `127.0.0.1:9200`。
- `secval-qdrant`：Qdrant 向量数据库，仅监听本机 `127.0.0.1:6333` 和 `127.0.0.1:6334`。

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

把待搜索的仓库放进 `data/repositories`，然后调用建库接口：

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
    -Uri http://127.0.0.1:8000/api/repositories/index `
    -ContentType application/json `
    -Body $body
```

`repository_path` 必须是 `data/repositories` 下的相对路径。API 会拒绝绝对路径和
越过挂载根目录的路径。同一 API 进程会串行导入，失败批次会从两个存储中回滚。

### 搜索

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

Java 当前会建立以下可搜索代码块：

- 文件头（包声明、导入和文件级注释）；
- 类、接口、枚举、注解类型、记录类型和模块；
- 方法、构造函数、字段、记录组件、枚举常量和注解元素；
- 静态初始化块、实例初始化块和匿名类。

类型代码块只保存声明头，方法和构造函数保存完整实现，避免把同一份方法体同时塞进
整类和整文件代码块。多字段声明只保存一个代码块，但会关联其中的全部字段符号。
import、参数、局部变量、Lambda 和注解的“使用位置”不会单独建符号，它们仍然保留在
所属声明的正文中并可被全文搜索。没有文件头的默认包文件会复用首个类型声明头建立
`file` 块；没有归入声明正文的独立尾部或间隔注释也会保留为 `file` 块。

查看状态：

```powershell
docker compose ps
```

停止服务但保留索引数据：

```powershell
docker compose down
```

本地开发暂时关闭了 OpenSearch Security 插件。这个配置不能直接用于生产环境，也不能把端口改成公网监听后继续使用。
