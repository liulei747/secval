# Search Web API

这个目录提供搜索板块的 HTTP API。

主要接口：

- `GET /api/health`：检查 OpenSearch、Qdrant、Neo4j 和 Joern。
- `POST /api/repositories/upload`：上传代码文件及相对路径。
- `POST /api/repositories/upload-zip`：安全检查并解压单个仓库 ZIP。
- `POST /api/repositories/index-jobs`：创建可查状态的后台索引任务。
- `GET /api/repositories/index-jobs/{job_id}`：读取后台索引状态。
- `POST /api/repositories/index-jobs/{job_id}/resume`：显式续跑被中断或失败的任务。
- `POST /api/repositories/index-jobs/{job_id}/cancel`：在提交新索引前请求安全取消。
- `POST /api/repositories/index-jobs/{job_id}/recover-stale`：双重确认失联后收口，不自动重跑。
- `POST /api/search`：执行 BM25、向量搜索和 RRF 合并。
- `/api/audits/*`：创建、查看、取消或续跑审计任务。
- `GET /docs`：FastAPI 自动生成的交互式接口文档。

应用启动时只创建一次 SearchRuntime 和本地 Embedding 模型，
后续请求会重复使用相同连接和模型。

仓库路径只能是容器 `/repositories` 下的相对路径。建议使用上传接口建立目录，
再创建后台索引任务；不接受宿主机绝对路径。

索引任务包含创建、开始、结束时间和完整阶段历史；失败时包含失败阶段。同一主机上的
后台接口和旧同步接口共用跨进程锁，不会同时替换索引。它不会跨主机排队，也不会自动续跑。
取消信号保存在SQLite，执行进程会在阶段边界处理；进入绑定或清理阶段后拒绝取消。
任务由工作进程原子认领，并返回执行者、尝试次数、心跳和租约到期时间。长步骤由后台
心跳线程续租；终态会清空租约。现阶段不会自动接管过期租约。

审计任务也有独立的执行者、心跳和租约。它们保存在`audit_task_runtime`表，不与调查
正文、证据和子Agent结果写在同一个JSON中。跨进程取消只修改运行表，避免覆盖刚保存的
调查进度；执行请求真正退出后再把取消状态和结束时间写回任务。

`POST /api/audits/{task_id}/recover-stale`只接受`lease_state=expired`的任务，并再次确认
进程锁无人持有。成功后只标记`interrupted`（已请求取消的任务标记`cancelled`），不会
调用模型或自动续跑。`missing`表示旧运行记录缺少租约，不能凭时间猜测接管。
