# SinkSpring 真实回归对照（2026-09-09）

本次任务 `e9c83bb13a86466fb92597ccef2b5c04` 与冻结基线任务 `6e253f09ae7d40e2b599c8a492b4ed4c` 使用相同仓库 `sinkspring-bench-eval`、快照 `sinkspring-bench-eval-v1`、审计目标、300 次调用上限、3600 秒时限和 3 个并行分工。

| 指标 | 冻结基线 | 本次真实任务 | 变化 |
|---|---:|---:|---:|
| 路径草图 / 验证 | 121 / 121 | 121 / 121 | 持平 |
| 候选 / 独立复核 | 43 / 43 | 20 / 20 | -23 / -23 |
| 正式 Finding | 36 | 16 | -20（-55.56%） |
| 模型调用 | 121 | 100 | -21（-17.36%） |
| Token | 1,360,846 | 1,145,338 | -215,508（-15.84%） |
| 墙钟时间 | 约 30 分钟 | 28 分 36.76 秒 | 约 -1 分 23 秒 |
| 完成状态 | report_submitted | partial_report | 回归 |
| 新内核运行状态 | 不适用 | 缺失 | K11 未接线 |

冻结基线的严格真值成绩为 31/35、代码召回 86.67%、配置召回 100%、安全控制误报 0/7。本次报告最终覆盖路径遍历、开放重定向、SSRF、XXE、反序列化、XSS、硬编码密钥和敏感数据暴露；SQL 注入、命令执行、表达式/模板/JNDI 注入、授权和配置类正式发现缺失，因此仅从正式 Finding 分布就能确认质量没有保持基线。私有 `sinkspring_expected.json` 当前不在工作区，不能诚实地产生可复现的精确 35 项评分；恢复该文件后必须用 `benchmarks/sinkspring_evaluate.py` 对 `report.json` 补跑，禁止用人工估算替代发布门禁。

本次任务有 11 次 `invalid_output`、2 次 `request_failed`，3 个 scope 子任务未交付。报告自身声明 `completeSecurityAudit=false`，文件语义审阅未完成。任务对象没有 `kernel_runtime` 字段，且实际入口仍走 `AuditService` → `AgentTeam`，所以该数据反映当前部署的旧 PathSketch 链路，不能归因于新分析内核。
