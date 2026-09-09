# SecVal 安全分析内核重构进度看板

状态日期：2026-09-09。架构定义见 [安全分析内核架构](security-analysis-kernel-architecture.md)。

## 状态规则

- TODO：尚未开始。
- DESIGN：正在设计契约或验证技术路线。
- DOING：已有实现，但未通过阶段门禁。
- BLOCKED：存在明确阻塞。
- DONE：代码、测试、盲测、文档和迁移全部完成。

任何项目不得因为“能跑”或 SinkSpring 分数提高而标为 DONE。

## 总览

| ID | 工作流 | 状态 | 完成标准 |
|---|---|---|---|
| K0 | 基线冻结与反过拟合治理 | DESIGN | 标记旧启发式来源，建立盲测与变体集 |
| K1 | 统一事实层契约 | TODO | 稳定节点、边、快照、解析状态契约 |
| K2 | 语义注册中心 | TODO | Model Pack、Control Contract、Invariant 的版本与审批 |
| K3 | Taint/Effect 分析器 | TODO | 双向 CPG 路径、taint kind、flow state |
| K4 | Guard/Dominance 分析器 | TODO | 支配、同值、失败终止与绕过路径 |
| K5 | Authorization 分析器 | TODO | Principal/Resource/Tenant/Operation/Guard |
| K6 | State Machine 分析器 | TODO | 状态转换与已确认业务不变量 |
| K7 | Race/Transaction 分析器 | TODO | READ-CHECK-WRITE、事务与原子控制 |
| K8 | Configuration 分析器 | TODO | 有效配置、覆盖链与资源暴露组合 |
| K9 | Structural/Dependency 分析器 | TODO | 局部语义与依赖可达性分级 |
| K10 | 统一 Candidate 与 Ledger | TODO | 结构化身份、补证、反证、六态裁决 |
| K11 | 审计运行时迁移 | TODO | 旧 PathSketch 流程逐步降级且兼容历史报告 |
| K12 | 盲测、性能和发布门禁 | TODO | 独立数据集、变体稳定率和资源预算达标 |

## K0：基线冻结与反过拟合治理

- [ ] 冻结当前 SinkSpring 历史回归基线。
- [ ] 为候选标注 deterministic、heuristic、graph、model、external 来源。
- [ ] 硬编码配置快速确认和固定 Sink 字符串降级为 bootstrap hint。
- [ ] 创建开发人员不可见答案的 Java/Spring 盲测集。
- [ ] 创建变量改名、方法封装、API 替换、目录重排和配置格式变化的 mutation 集。
- [ ] CI 检查运行代码不得包含 benchmark 路由、类名和标准项 ID。

门禁：盲测与 mutation 评估器能够独立运行，否则不进入分析器召回验收。

## K1：统一事实层

- [ ] 定义 FactNode、FactEdge、SourceLocation、FactConfidence、ParseGap。
- [ ] 定义调用、参数、返回、定义使用、控制、覆盖和配置等边。
- [ ] Joern CPG、Neo4j 和 Tree-sitter 适配统一契约。
- [ ] 建立稳定节点 ID、快照隔离和事实失效机制。
- [ ] 暴露解析成功、失败、缺失依赖和动态未知覆盖。

门禁：同一快照重复构建 ID 稳定；不同快照不串线；反例不产生伪边；解析缺口可见。

## K2：语义注册中心

- [ ] 定义 Framework Model Pack schema。
- [ ] 定义 Source、Effect、Propagator、Sanitizer、Validator 和认证上下文。
- [ ] 定义 Control Contract 的 flow state 和失败行为。
- [ ] 定义 Business Invariant 的 PROPOSED、VERIFIED、REJECTED 生命周期。
- [ ] 支持语言、框架、版本、项目扩展优先级和冲突检测。

门禁：每个模型包含正例、反例、包装、继承、重载和版本测试；LLM 不能直接启用模型。

## K3—K9：专用分析器

建议顺序：Taint → Guard → Authorization → Configuration → Structural/Dependency → State → Race。

每个分析器统一检查：

- [ ] 输入只来自 facts 与 semantics 接口。
- [ ] 输出符合统一 Candidate 契约。
- [ ] 支持证据和反证都有节点与位置。
- [ ] 未知调用、缺失依赖和配置前提不会被判为安全。
- [ ] 具备单元、集成、Docker、盲测和 mutation 测试。
- [ ] 记录准确率、召回率、未知率、时间和峰值内存。
- [ ] 无目标项目名称、路由、类名或标准答案字段。

## K10：统一 Candidate 与六态 Ledger

- [ ] Candidate 使用结构化入口、主体、路径、操作、控制和根因节点。
- [ ] 身份不依赖标题、自然语言路由或固定 Sink 关键词。
- [ ] 多分析器结果合并并保留 provenance。
- [ ] Need Planner 定向生成调用者、callee、身份、资源、profile、事务和控制补证项。
- [ ] Counterevidence Runner 主动验证全局控制和安全分支。
- [ ] 实现 CONFIRMED、REJECTED、UNREACHABLE、DEFENDED、DUPLICATE、NEEDS_REVIEW。
- [ ] 裁决追加写、可追溯并能因依赖闭包变化失效。
- [ ] 报告完全由 Ledger 确定性生成。

门禁：同一根因稳定合并；不同根因不误合并；未找到入口不得成为 UNREACHABLE。

## K11：运行时迁移

- [ ] 新旧引擎双跑且分别统计。
- [ ] 旧 PathSketch 报告保持只读兼容。
- [ ] Candidate Ledger 接入任务、预算、续跑和独立复核。
- [ ] 按分析器和候选保存检查点。
- [ ] 新引擎通过门禁后逐项关闭旧启发式确认能力。

## K12：发布质量门禁

| 指标 | 第一阶段 | 发布要求 |
|---|---:|---:|
| 盲测路径召回 | ≥ 70% | ≥ 85% |
| 安全控制误报率 | ≤ 10% | ≤ 5% |
| mutation 稳定率 | ≥ 80% | ≥ 95% |
| 正式 Finding 证据完整率 | 100% | 100% |
| 未知项可解释率 | 100% | 100% |
| 同根因重复率 | ≤ 5% | ≤ 2% |
| benchmark 专名进入运行代码 | 0 | 0 |

性能目标在取得真实基线后确定，不通过缩小分析范围制造达标结果。每次发布保存评估数据、版本、硬件、配置、失败样本和回归差异。

## 当前下一步

1. 完成 K0 的来源标注契约和盲测隔离设计。
2. 为 K1 写 FactNode/FactEdge ADR 与最小接口测试。
3. 用现有 Joern 对非 SinkSpring 小项目输出第一条结构化跨过程事实路径。
4. 在任何新漏洞规则实现前完成 mutation runner。

