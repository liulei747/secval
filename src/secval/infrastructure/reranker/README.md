# 重排序实现

- `none`：保留RRF结果。
- `local`：本地CrossEncoder打分。
- `api`：独立聊天请求，让模型返回候选编号的完整排序。

Docker当前使用 `api / glm-5.3-flash`，复用环境变量
`SECVAL_EMBEDDING_API_URL` 和 `SECVAL_EMBEDDING_API_KEY`。
基础URL追加 `/chat/completions`；如果填写的是 `/embeddings` 完整地址，先替换端点。
不需要重新生成向量或重新建索引。恢复本地模式只需在
`config/search.docker.yaml` 中把 provider 改回 local、model_name 改回
BAAI/bge-reranker-base，再重启API。

API每次接收查询与前10个候选（候选数由candidate_count控制），每个代码块最多6000字符，
并标注是否截断。API模式不使用本地的max_sequence_length、device和batch_size参数。
不共享审计Agent上下文，但候选源码会发送给已配置的远端服务。
模型必须返回所有候选编号的无重复排列。失败/超时由搜索服务回退到RRF，
回退结果的reranker_score为null。超时设置为60秒（HTTP socket超时，不是严格总时限）。

API的reranker_score是1/排名，只表达顺序，不是模型置信度，也不能与本地模型分数比较。
保持候选数量不变仅方便对照；API输入长度/格式与本地模型不同，不能据此独立归因模型能力。

2026-09-04实测“用户登录”：API成功排序（未回退），端到端约36.19秒，
第1为LoginController类，第2为AuthorizingRealm.getUserInfo；仍不能认为准确性问题已解决。
