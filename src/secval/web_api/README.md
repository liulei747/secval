# Search Web API

这个目录提供搜索板块的 HTTP API。

当前接口：

- `GET /api/health`：检查 OpenSearch 和 Qdrant。
- `POST /api/search`：执行 BM25、向量搜索和 RRF 合并。
- `GET /docs`：FastAPI 自动生成的交互式接口文档。

应用启动时只创建一次 SearchRuntime 和本地 Embedding 模型，
后续请求会重复使用相同连接和模型。

仓库登记和后台索引任务尚未加入，不能通过当前 API 扫描服务器目录。
