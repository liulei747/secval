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

