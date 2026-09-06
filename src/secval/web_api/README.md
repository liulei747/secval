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
- `POST /api/code-graph/symbols`：查询指定索引批次中的符号声明。
- `POST /api/code-graph/callers`：查询指定索引批次中的静态调用者候选。
- `POST /api/code-graph/callees`：查询指定调用者静态指向的目标符号候选。
- `POST /api/code-graph/type-relations`：查询继承、实现和方法覆盖关系。
- `POST /api/code-graph/dispatch-targets`：查询同名方法的动态分派实现候选。
- `/api/audits/*`：创建、查看、取消或续跑审计任务。
- `GET /api/audit-settings`：查看不含地址和密钥的审计模型运行配置。
- `GET /api/task-queues`：索引与审计的队列深度统计（queued/running）。
- `GET /api/repositories/index-runs`：列出仓库/快照仍有源码绑定的索引批次。
- `GET /graph`：代码关系查询页面（只读，不显示源码正文）。
- `GET /docs`：FastAPI 自动生成的交互式接口文档。

应用启动时只创建一次 SearchRuntime 和本地 Embedding 模型，
后续请求会重复使用相同连接和模型。

仓库路径只能是容器 `/repositories` 下的相对路径。建议使用上传接口建立目录，
再创建后台索引任务；不接受宿主机绝对路径。

索引任务包含创建、开始、结束时间和完整阶段历史；失败时包含失败阶段。同一主机上的
后台接口和旧同步接口共用跨进程锁，不会同时替换索引。它不会跨主机排队，也不会自动续跑。
索引请求先持久化排队：忙碌时新任务保留在队列中并显示位置，空闲Worker按创建顺序认领。
重启后遗留的queued任务会被自动消费；只有running任务才标记中断并要求显式续跑。
取消信号保存在SQLite，执行进程会在阶段边界处理；进入绑定或清理阶段后拒绝取消。
任务由工作进程原子认领，并返回执行者、尝试次数、心跳和租约到期时间。长步骤由后台
心跳线程续租；终态会清空租约。现阶段不会自动接管过期租约。

审计任务也有独立的执行者、心跳和租约。它们保存在`audit_task_runtime`表，不与调查
正文、证据和子Agent结果写在同一个JSON中。跨进程取消只修改运行表，避免覆盖刚保存的
调查进度；执行请求真正退出后再把取消状态和结束时间写回任务。

`POST /api/audits/{task_id}/recover-stale`只接受`lease_state=expired`的任务，并再次确认
进程锁无人持有。成功后只标记`interrupted`（已请求取消的任务标记`cancelled`），不会
调用模型或自动续跑。`missing`表示旧运行记录缺少租约，不能凭时间猜测接管。

审计请求同样先持久化排队：同一时间仍只执行一个审计，忙碌时新任务保持`queued`，
空闲Worker按创建顺序原子认领。取证工具只在执行时创建；排队中取消直接收口。
审计任务详情包含`queue_position`；`/api/task-queues`返回两类任务的队列深度。

审计模型工具协议默认使用`SECVAL_AUDIT_TOOL_PROTOCOL=json`，兼容只接受正文JSON的供应商。
明确确认供应商支持OpenAI兼容`tools/tool_calls`后，可设置为`native`：源码读取、搜索、
Neo4j和Joern等只读取证工具会使用原生函数调用，下一轮以同一`tool_call_id`回传工具结果；
边界、调查、审阅记录和最终报告仍由后端严格JSON契约校验。原生协议暂不与
`SECVAL_AUDIT_STREAM=true`同时启用，配置冲突会拒绝启动，不会暗中降级。
实际发送的函数还会按任务`scope_info.tools`裁剪；未部署或未绑定的能力不会出现在请求中。
审计页面通过`GET /api/audit-settings`展示当前模型名、协议、流式开关、超时和输出上限，
以及连接信息是否已经配置；接口不会返回API地址或密钥正文。

审计内部的Neo4j只读工具包括`find_code_relations`、`find_code_callers`和
`find_code_callees`。后两者分别向上查调用者、向下查目标，但不开放任意Cypher。它们按
短方法名关联，同名或重载方法可能返回多个候选，Agent必须继续用`read_file`读取同一
固定快照后才能把它写成证据。
