# SecVal 安全分析内核重构进度看板

状态日期：2026-09-10。架构定义见 [安全分析内核架构](security-analysis-kernel-architecture.md)。

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
| K0 | 基线冻结与反过拟合治理 | DONE | 标记旧启发式来源，建立盲测与变体集 |
| K1 | 统一事实层契约 | DONE | 稳定节点、边、快照、解析状态契约 |
| K2 | 语义注册中心 | DONE | Model Pack、Control Contract、Invariant 的版本与审批 |
| K3 | Taint/Effect 分析器 | DONE | 双向 CPG 路径、taint kind、flow state |
| K4 | Guard/Dominance 分析器 | DONE | 支配、同值、失败终止与绕过路径 |
| K5 | Authorization 分析器 | DONE | Principal/Resource/Tenant/Operation/Guard |
| K6 | State Machine 分析器 | DONE | 状态转换与已确认业务不变量 |
| K7 | Race/Transaction 分析器 | DONE | READ-CHECK-WRITE、事务与原子控制 |
| K8 | Configuration 分析器 | DONE | 有效配置、覆盖链与资源暴露组合 |
| K9 | Structural/Dependency 分析器 | DONE | 局部语义与依赖可达性分级 |
| K10 | 统一 Candidate 与 Ledger | DONE | 结构化身份、补证、反证、六态裁决 |
| K11 | 审计运行时迁移 | DOING | 旧 PathSketch 流程逐步降级且兼容历史报告 |
| K12 | 盲测、性能和发布门禁 | DOING | 独立数据集、变体稳定率和资源预算达标 |

## K0：基线冻结与反过拟合治理

- [x] 冻结当前 SinkSpring 历史回归基线。
- [x] 为候选标注 deterministic、heuristic、graph、model、external 来源。
- [x] 硬编码配置快速确认和固定 Sink 字符串降级为 bootstrap hint。
- [x] 创建开发人员不可见答案的 Java/Spring 盲测集。
- [x] 创建变量改名、方法封装、API 替换、目录重排和配置格式变化的 mutation 集。
- [x] CI 检查运行代码不得包含 benchmark 路由、类名和标准项 ID。

门禁：盲测与 mutation 评估器能够独立运行，否则不进入分析器召回验收。

## K1：统一事实层

- [x] 定义 FactNode、FactEdge、SourceLocation、FactConfidence、ParseGap。
- [x] 定义调用、参数、返回、定义使用、控制、覆盖和配置等边。
- [x] Joern CPG、Neo4j 和 Tree-sitter 适配统一契约。
- [x] 建立稳定节点 ID、快照隔离和事实失效机制。
- [x] 暴露解析成功、失败、缺失依赖和动态未知覆盖。

门禁：同一快照重复构建 ID 稳定；不同快照不串线；反例不产生伪边；解析缺口可见。

## K2：语义注册中心

- [x] 定义 Framework Model Pack schema。
- [x] 定义 Source、Effect、Propagator、Sanitizer、Validator 和认证上下文。
- [x] 定义 Control Contract 的 flow state 和失败行为。
- [x] 定义 Business Invariant 的 PROPOSED、VERIFIED、REJECTED 生命周期。
- [x] 支持语言、框架、版本、项目扩展优先级和冲突检测。

门禁：每个模型包含正例、反例、包装、继承、重载和版本测试；LLM 不能直接启用模型。

## K3—K9：专用分析器

建议顺序：Taint → Guard → Authorization → Configuration → Structural/Dependency → State → Race。

### K3：Taint/Effect

- [x] 使用 VERIFIED Source、Effect、Sanitizer 完整签名模型。
- [x] 按 taint kind 执行 Source 正向与 Effect 反向事实图求交。
- [x] 传播参数、返回和定义使用边，并在候选中保存 flow state。
- [x] 有效 sanitizer 产生带节点位置的反证，且只阻断适用 taint kind。
- [x] 缺失依赖、动态调用和 native 边界产生 UNKNOWN_EFFECT/NEEDS_REVIEW。
- [x] 输出统一 Candidate 结构化身份、完整路径、位置和 provenance。
- [x] 正例、反例、包装、继承、重载、版本、盲测、mutation 和 Docker 门禁通过。
- [x] 记录候选数、阻断数、未知率、耗时和峰值内存。

K3 门禁结果：本地阶段回归 187 项、生产镜像一次性测试容器 41 项通过；三个盲测结果与外部承诺一致，四类结构 mutation 稳定率 100%，安全控制误报 0，未知效果解释率 100%。该小样本只证明阶段门禁，不外推为发布准确率。

### K4：Guard/Dominance

- [x] 从 `FLOWS_TO` 事实构建 CFG 可达关系并计算 dominator。
- [x] 验证 Guard 支配 Effect、检查同一值且失败分支终止。
- [x] 主动搜索排除 Guard 后仍可到达 Effect 的绕过路径。
- [x] 有效控制输出带 Guard/Effect 位置的反证；无效或缺失控制输出统一 Candidate。
- [x] 缺少 Control Contract 时保持 NEEDS_REVIEW，不判定安全。
- [x] 正例、反例、包装、继承、重载、盲测、mutation、Docker 和资源指标门禁通过。

K4 门禁结果：缺失控制、有效控制和未知控制三个盲测与外部承诺一致；重命名、包装、继承和重载变体稳定；生产镜像一次性测试容器 49 项通过。指标记录 Effect、Candidate、DEFENDED、bypass path、耗时和峰值内存。

### K5：Authorization

- [x] 建立 Principal、Resource、Operation 和 Guard 的结构化关系。
- [x] 区分服务端认证主体、客户端可控主体和未知主体。
- [x] 分别验证 ownership、tenant、role 和 permission 约束。
- [x] 只接受支配操作、检查同一资源且失败终止的 Guard 证明。
- [x] Guard 绕过、缺失主体/资源/契约和未知信任均保持候选或 NEEDS_REVIEW。
- [x] 输出统一 Candidate、授权证据/反证、源码位置和 provenance。
- [x] IDOR、租户逃逸、功能授权、角色提升、安全控制、结构变体、盲测、Docker 和资源指标门禁通过。

K5 门禁结果：缺少 ownership、有效 ownership 和未知身份/契约三个盲测与外部承诺一致；客户端主体不能冒充认证上下文；本地分析器与质量门禁 33 项、生产镜像一次性测试容器 59 项通过。

### K8：Configuration

- [x] YAML、Properties、JSON、XML 和 TOML 生成统一 ConfigNode；环境、命令行和部署值由调用方显式传入。
- [x] 按 base、profile、环境变量、命令行和部署优先级解析有效值并建立 OVERRIDES 链。
- [x] 框架绑定建立 CONFIGURES、EXPOSES 和 PROTECTS 关系。
- [x] VERIFIED 配置策略查询“启用 + 暴露 + 缺少控制”组合，并受证据和非 LLM 审批约束。
- [x] 输出原始值、有效值、覆盖链、消费组件、资源、控制、部署前提、位置和 provenance。
- [x] 解析失败、缺失值和无法解析的占位符形成 ParseGap 或 NEEDS_REVIEW，不能证明安全。
- [x] 正例、反例、五种格式 mutation、覆盖优先级、控制有效性、盲测、Docker 和资源指标门禁通过。

K8 门禁结果：危险组合、安全部署覆盖和未知占位符三个盲测与外部承诺一致，样本准确率和支持项召回率均为 100%；五种配置格式产生等价判断；本地 K0–K8 阶段集合 96 项、生产镜像一次性测试容器 96 项通过。运行代码 benchmark 专名泄漏为 0，候选均保留源码位置和未知原因。该小样本只证明阶段门禁，不外推为发布准确率。

### K9：Structural/Dependency

- [x] 结构分析使用完整签名、解析类型、常量传播和安全使用上下文，不依赖方法名关键词。
- [x] 弱值经包装/改名后的 DEFINES_USES 链可追踪；安全值、非安全用途和不同重载形成反证。
- [x] requirements、npm lockfile、Maven manifest 和 CycloneDX SBOM 生成统一 Dependency facts。
- [x] VERIFIED advisory 绑定包、版本范围、漏洞完整签名和可选运行激活条件。
- [x] 区分依赖存在、漏洞 API 被调用、外部入口可达、运行配置激活四级证据。
- [x] 未锁定版本、缺失 API 事实和未知运行配置保持 ParseGap 或 NEEDS_REVIEW。
- [x] 输出统一 Candidate、证据/反证、源码位置、provenance、耗时和峰值内存。
- [x] 正例、反例、包装、改名、继承解析、重载、版本、SBOM、盲测、mutation 和 Docker 门禁通过。

K9 门禁结果：结构与依赖各自的支持、反证和未知共六个盲测均与独立承诺一致，样本准确率与支持项召回率均为 100%；本地 K0–K9 阶段集合 112 项、生产镜像一次性测试容器 112 项通过。运行代码 benchmark 专名泄漏为 0，四级依赖证据与所有未知原因均可解释。该小样本只证明阶段门禁，不外推为发布准确率。

### K6：State Machine

- [x] 以 READS_STATE、Operation、WRITES_STATE 和 CAUSES_EFFECT 事实形成完整转换。
- [x] VERIFIED 状态不变量声明实体、操作、允许前后状态、前置条件、重复性和必要副作用。
- [x] 检测非法来源状态、非法目标状态、缺少前置条件、缺少副作用和无幂等保护的重复执行。
- [x] 未知初始/目标状态保持 NEEDS_REVIEW，不能作为安全反证。
- [x] 有效转换与有效幂等控制输出绑定位置的反证。
- [x] LLM 提议只能保持 PROPOSED，启用必须具备证据和非 LLM 审批。
- [x] 输出实体、操作、前后状态、条件、副作用、控制、违规、未知、位置和 provenance。
- [x] 正例、反例、改名、包装、状态序列、重复执行、控制有效性、盲测、Docker 和资源门禁通过。

K6 门禁结果：缺少业务前置条件、完整安全转换和未知初始状态三个盲测与独立承诺一致，样本准确率与支持项召回率均为 100%；本地 K0–K9 累计阶段集合 123 项、生产镜像一次性测试容器 123 项通过。运行代码 benchmark 专名泄漏为 0，状态违规和未知原因均可解释。该小样本只证明阶段门禁，不外推为发布准确率。

### K7：Race/Transaction

- [x] 以 READS_RESOURCE、CHECKS_RESOURCE、WRITES_RESOURCE 和 IN_TRANSACTION 事实识别并发敏感操作。
- [x] 验证读、检查和写绑定同一稳定资源身份，跨资源检查不能保护写入。
- [x] VERIFIED 并发不变量声明实体操作、事务要求、可接受隔离级别和控制。
- [x] 分别验证行锁、版本字段、唯一约束、原子更新、幂等键和 serializable 隔离级别。
- [x] 缺失事务、跨资源检查和缺少原子控制形成精确违规候选。
- [x] 缺失 READ/CHECK/WRITE 事实或未知运行隔离级别保持 NEEDS_REVIEW。
- [x] 有效控制输出绑定资源、事务和源码位置的反证；LLM 不变量不能自行启用。
- [x] 正例、反例、改名、事务包装、控制 mutation、盲测、Docker 和资源门禁通过。

K7 门禁结果：无并发控制、有效原子控制和未知隔离级别三个盲测与独立承诺一致，样本准确率与支持项召回率均为 100%；本地 K0–K9 累计阶段集合 135 项、生产镜像一次性测试容器 135 项通过。运行代码 benchmark 专名泄漏为 0，事务、资源身份、控制和未知前提均可解释。该小样本只证明阶段门禁，不外推为发布准确率。

每个分析器统一检查：

- [x] 输入只来自 facts 与 semantics 接口。
- [x] 输出符合统一 Candidate 契约。
- [x] 支持证据和反证都有节点与位置。
- [x] 未知调用、缺失依赖和配置前提不会被判为安全。
- [x] 具备单元、集成、Docker、盲测和 mutation 测试。
- [x] 记录准确率、召回率、未知率、时间和峰值内存。
- [x] 无目标项目名称、路由、类名或标准答案字段。

## K10：统一 Candidate 与六态 Ledger

- [x] Candidate 使用结构化入口、主体、路径、操作、控制、资源和根因节点。
- [x] 身份不依赖标题、自然语言路由或固定 Sink 关键词。
- [x] 多分析器路径变体按结构化身份合并并保留 provenance。
- [x] Need Planner 定向生成调用者、callee、身份、资源、profile、事务和控制补证项。
- [x] Counterevidence Runner 主动验证全局控制和安全分支。
- [x] 实现 CONFIRMED、REJECTED、UNREACHABLE、DEFENDED、DUPLICATE、NEEDS_REVIEW。
- [x] 裁决哈希链追加写、可追溯并能因依赖闭包变化失效。
- [x] JSON 与 Markdown 报告完全由 Ledger 确定性生成。

门禁：同一根因稳定合并；不同根因不误合并；未找到入口不得成为 UNREACHABLE。

K10 门禁结果：同身份路径变体稳定合并、不同资源保持分离；六态均执行证据前提，未证明入口缺失不能标记 UNREACHABLE；危险、受保护和未知三个 Ledger 盲测与独立承诺一致。本地累计阶段集合 141 项、生产镜像一次性测试容器 141 项通过，事件哈希链和确定性报告验证通过。

## K11：运行时迁移

- [x] 新旧引擎双跑且分别统计。
- [x] 旧 PathSketch 报告保持只读兼容。
- [x] Candidate Ledger 接入任务、预算、续跑和独立复核边界。
- [x] 按分析器和候选保存原子检查点。
- [x] 新引擎通过门禁后关闭旧启发式确认能力，旧结果仅保留 bootstrap hint。

K11 组件门禁结果：预算耗尽后续跑只执行未完成分析器，逐候选检查点可恢复且跨快照复用被拒绝；历史 schema-v3 报告通过复制视图保持只读兼容；旧启发式无法进入 CandidateLedger。完整运行、旧提示隔离和未知候选三个盲测与独立承诺一致；本地累计阶段集合 146 项、生产镜像一次性测试容器 146 项通过。

K11 真实入口接线门禁已通过：2026-09-10 的同快照真实任务 `cfce77188f06437081e3714467c8a402` 由 `AuditService` 执行 Kernel runtime，8 个分析器全部完成，生成 3 个 Ledger 候选和 3 个追加事件，哈希链验证通过；事实快照包含 345 个节点、72 条边和 0 个 ParseGap，旧流程被明确记录为 128 个 bootstrap hint 且 `confirmation_capability=false`，历史报告视图为只读。K11 仍为 DOING：除 Configuration 外的生产 facts 尚未携带各分析器需要的 Source、Effect、Operation、State、Resource 等语义，七个分析器在真实任务上均为零输入；旧报告仍承担正式 Finding 输出，尚未完成新 Ledger 的生产替换。

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

召回率低于 85% 时必须继续迭代，直到使用仓库外私有真值的严格评分达到门限。优化只能作用于通用能力：解析与事实完整性、完整签名语义模型、跨过程/跨文件传播、控制与反证识别、未知项补证和确定性裁决。禁止加入 benchmark 项目名、类名、路由、常量、答案 ID、固定漏洞位置或从私有真值反推的专用规则；每次召回改动必须同时通过隔离盲测、五类 mutation、反例误报和运行代码专名泄漏门禁。

K12 组件门禁结果：聚合 9 个独立盲测套件共 30 次执行，路径召回 100%，安全控制误报率 0%，五类 mutation 稳定率 100%，正式结果证据完整率与未知项可解释率均为 100%，同根因重复率 0%，运行代码 benchmark 专名泄漏 0。评估范围 35 单元与冻结基线一致；最大分析耗时 1.259 ms，峰值分配 5,047 bytes，低于 100 ms 与 1 MiB 的版本化门限。本地与生产镜像累计组件门禁均为 151 项通过。

K12 发布门禁未通过：同输入、同快照、同预算的最终续跑任务形成 128 条 PathSketch 且 128 条全部完成验证，34 个候选全部独立复核，产出 20 个正式 Finding；相比冻结基线的 36 个仍少 16 个。报告仍为 `partial_report`，7 个调查因独立证据不足未收口，同时缺少完整文件审阅声明、独立基线问题和结构化威胁模型。私有真值文件仍不在仓库，无法诚实复算冻结的 31/35 与 0/7 严格分数；在生产语义 facts 接通并使用同一私有真值评分前，不允许发布。

## 当前下一步

1. 将 Tree-sitter/Joern/配置与依赖前端产出的生产 facts 补齐为 Source、Effect、Guard、Principal、Operation、State 和 Resource 语义，使八个分析器在真实仓库上拥有非空、可解释输入。
2. 将 CandidateLedger 的裁决结果接管正式 Finding 发布，旧 PathSketch 仅保留 bootstrap hint 和只读历史视图，完成 K11 迁移门禁。
3. 恢复私有真值文件后运行 `benchmarks/sinkspring_evaluate.py`，与冻结的 31/35、0/7 基线作严格比较；同时收口 7 个独立复核缺口、文件审阅、基线和威胁模型，K12 达标后才能恢复 DONE。

## 2026-09-09 实施记录

- 新增受控候选来源契约，生成者 ID 与 deterministic、heuristic、graph、model、external 类型分离；heuristic 和 model 只能声明 `bootstrap_hint`，不能冒充确认事实。
- 旧固定 Sink 清单改名为 `legacy_sink_bootstrap` 并标为 heuristic；硬编码配置匹配改为 `inconclusive`，等待 Configuration Engine 验证覆盖链、消费组件和部署暴露。
- 新增独立 mutation runner，支持标识符改名、API 替换、唯一文本包装和目录移动；拒绝原地写入、路径越界、覆盖已有输出和无效变体。
- 新增可由 CI 调用的运行代码 benchmark 专名泄漏门禁；当前清单扫描结果为 0 泄漏。仓库尚无 CI 配置，因此 CI 条目保持未勾选。盲测输入/oracle 隔离规则已成文，但独立盲测集尚未建立。
- 新增 K1 ADR、最小 facts 契约和参考内存存储；契约测试覆盖重复构建 ID 稳定、跨快照端点拒绝、解析缺口可查询和源码路径约束。
- 冻结历史 SinkSpring 回归基线及源产物 SHA-256；该基线只作回归，不具备规则批准能力。
- 建立三个无明文 oracle 的 Java/Spring 盲测源码包。仓库仅保存答案承诺；评分器要求结果冻结后从盲测目录外提供 oracle，并验证承诺后评分。
- mutation suite 的五类独立变体已由同一 runner 成功生成；自动门禁执行来源契约、盲测隔离、基线完整性、mutation 和事实层测试。
- K1 新增 Tree-sitter、Neo4j、Joern 适配器及统一 `FactSnapshotBuilder`。未解析调用端点不会产生边，而是形成 `missing_dependency`；解析失败和动态调用同样进入覆盖汇总。重建先精确失效当前 snapshot，不影响其他快照。
- K2 新增版本化 Model Pack、Framework Model、Control Contract 和 Business Invariant 注册中心。VERIFIED 模型强制要求六类测试、证据和非 LLM 审批；项目扩展按受控优先级覆盖同签名框架语义，同层冲突直接拒绝。
- K3 新增按 taint kind 隔离的双向 Taint/Effect Engine、统一 Candidate 最小契约、sanitizer 反证和 UNKNOWN_EFFECT 保留。新镜像部署健康，容器门禁、盲测、mutation 与资源指标均已通过。
- K4 新增基于 CFG 的 Guard/Dominance Engine，验证支配、同值、失败终止和绕过路径；新镜像内阶段测试通过，部署健康。
- K5 新增 Authorization Engine，区分主体信任并验证 ownership、tenant、role、permission 与 Guard 支配关系；盲测、变体和容器门禁通过。
- K8 新增 Configuration Engine，将五种文件格式和显式运行时覆盖归一为 ConfigNode 与覆盖链；版本化策略验证启用、暴露和保护组合，未知配置保持 NEEDS_REVIEW；盲测、格式变体、本地与容器门禁通过。
- K9 新增 Structural 与 Dependency Reachability Engine：前者验证完整签名、跨包装常量传播及安全使用上下文，后者归一 manifest/lockfile/SBOM 并提供依赖存在到运行激活的四级证据；六个盲测和本地/容器门禁通过。
- K6 新增 State Machine Engine，以显式状态读写、操作和副作用事实验证已审批业务不变量；非法跳转、前置条件缺失、重复执行和未知状态均形成可解释结果，盲测及本地/容器门禁通过。
- K7 新增 Race/Transaction Engine，验证同资源 READ-CHECK-WRITE、事务边界、隔离级别与五类原子控制；危险、受保护及未知隔离盲测和本地/容器门禁通过。
- K10 新增结构化 Candidate 合并、定向 Need Planner、Counterevidence Runner 和六态追加式 Ledger；闭包变化会追加 NEEDS_REVIEW，报告由 Ledger 确定性生成，盲测及本地/容器门禁通过。
- K11 新增预算化 KernelMigrationRuntime、逐分析器/候选原子检查点、快照安全续跑及旧报告只读桥接；新旧指标分离且旧启发式确认能力关闭，盲测及本地/容器门禁通过。
- K12 新增聚合发布门禁和可复现评估产物；30 次盲测、五类 mutation、质量阈值、范围防缩减、时间与内存预算等组件检查通过，本地和生产容器累计组件测试 151 项通过；真实发布门禁状态以下一条记录为准。
- 真实回归任务 `e9c83bb13a86466fb92597ccef2b5c04` 使用与冻结任务相同的仓库、快照、目标和预算运行 28 分 36.76 秒：121 条 PathSketch 全部验证，20 个候选全部复核，100 次模型调用、1,145,338 Token，最终 16 个正式 Finding；11 次输出无效、2 次请求失败、3 个 scope 子任务失败，报告为 `partial_report`。
- 真实任务状态中没有 `kernel_runtime` 和 `legacy_report_read_only`，源码调用链也未从 `AuditService` 引用 `KernelMigrationRuntime`。据此撤销 K11/K12 的 DONE，组件门禁保留，真实集成和发布门禁改为 DOING。原始报告与机器可读指标保存在 `benchmarks/kernel_quality/results/real-sinkspring-2026-09-09/`。
- 2026-09-10 完成真实入口接线、Ledger 快照续跑、运行时签名失效、Neo4j 调用边导出和冻结源码事实装配；生产镜像相关门禁 160 项通过，续跑专项门禁 4 项、路径与 Kernel 集成门禁 31 项通过。
- 修复续跑把无结果失败分片误标为 `canonical_candidate_ready`、格式修复第 5 次调用不可达、未知候选类型导致整包丢弃，以及新增草图复用已完成验证包 ID 后无法重新调度四个真实缺陷。
- 最终真实续跑任务 `cfce77188f06437081e3714467c8a402` 完成 128/128 路径验证、34/34 候选独立复核并产出 20 个正式 Finding；Kernel 8/8 分析器完成，Ledger 3 个候选/3 个事件且哈希链有效，事实覆盖 345 节点/72 边/0 ParseGap。产物保存在 `benchmarks/kernel_quality/results/real-sinkspring-k11-final-2026-09-10/`。
- 2026-09-10 覆盖缺口修复：PathSketch 模式恢复独立基线 worker，避免包内验证替代独立漏检检查；Finding 身份增加稳定语义 Sink/入口锚点，并以 canonical `findingId` 兜底合并，消除同一配置文件首行多项缺陷的身份碰撞与重复导出。
- 生产事实装配现已读取 Maven `pom.xml`、npm `package-lock.json`、锁定的 `requirements.txt` 与 CycloneDX JSON。Java/Spring 前端开始生成保守的 HTTP Source、SQL/命令/文件/网络/XML/反序列化/JNDI/模板 Effect，并把已解析跨方法调用投影为候选数据流；该层只产生 `NEEDS_REVIEW`，不能绕过独立复核。对于尚未产出 Authorization、Guard、State 或其他语义输入的族，Kernel 写入确定性的 semantic coverage gap，结构解析成功不再显示为安全语义完整。此项尚未宣称 K12 达标；必须完成真实复测并用仓库外私有真值评分。
- Java/Spring 授权事实开始识别同时包含客户端身份头和路径资源 ID 的 HTTP 操作，显式生成 `client_controlled` Principal、Resource 与 ownership Requirement。离线 SinkSpring 快照识别出 2 个待复核授权操作；没有客户端身份头的普通路径参数不会被推断成该类候选。Source 与 Effect、Resource 等输入族分别统计 semantic gap，避免其中一侧存在时掩盖另一侧缺失。
- Guard 前端开始识别 Principal 与路径 Resource 的同值比较，只有否定分支明确 `throw`/`return` 时才生成终止型 identity guard；控制流只连接 Source→Guard→Operation，不保留绕过边。经验证的 Guard 契约可让 GuardEngine 输出支配、同值、失败终止且无绕过路径的反证；单纯比较或不终止分支不会被当作有效控制。
- Principal 信任不再一律按请求头处理：仅观察到明确的 `verifySession`、`verifyToken` 或 `authenticate` 调用且参数是同一个请求头变量时，才升级为 `server_authenticated`；只解码或直接读取声明仍保持 `client_controlled`。身份验证不会自动证明资源归属，缺少 ownership Guard 时仍生成对象授权候选。
- 独立基线 worker 的一次性报告前收尾现覆盖 `worker_step_limit` 和已保存上下文的 `model_output_truncated`，并优先于普通发现 worker；真实续跑 `6da55ab949854d2b8523341cfe5dc590` 已提交 6 个基线问题，消除了“独立基线尚未提交”原因。
- 报告组装可从带源码证据的边界台账确定性派生结构化威胁模型，并明确保留未登记部署边界为未知项；主模型漏调 `record_threat_model` 不再产生空模型。基线问题仅在标准化 API 路由精确重合时自动补充来源关联，宽泛问题继续保留为缺口。
- 明确写出 XXE、SSRF、XSS、SQL/命令注入、路径穿越、反序列化、JWT/IDOR、硬编码凭据及配置缺陷的 `unknown` PathSketch 会在验证前保守归一化；无法唯一判断的类型仍保持 `unknown`。真实报告离线重算可精确关联 4/6 个基线问题，并成功派生 30 个边界的结构化威胁模型。
- 独立复核现按漏洞语义补入标准依赖清单和已批准配置；`pom.xml`、Gradle/npm/Python/Cargo/Go 锁文件及 CycloneDX `bom.json` 被视为只读程序描述符，普通配置与密钥文件仍需显式批准。批准路径本身和基线来源关联不再污染复核输入哈希，只有实际新增证据才使缓存失效。
- 补证后的检查点续跑 `94dab10a326646bb959e9d5776f9b1cc` 用 12 次模型调用完成 61 项复核，其中 21 个复核包实际包含 `pom.xml`；正式 Finding 为 38 个且 ID 全部唯一，supported/refuted/inconclusive 为 51/1/9，仍有 3 个请求级复核失败。产物保存在 `benchmarks/kernel_quality/results/real-sinkspring-review-context-fixed-2026-09-10/`。
- 大范围续跑新增独立整文件审阅 worker：只计算受支持源码、可执行构建描述符及用户批准配置，`.gitignore`、IDE 元数据和纯数据 SQL 不再错误进入完成分母；已完成文件按内容摘要登记，最多四个并行有界证据包，后续续跑继续处理剩余项。
- 针对 Controller/Mapper 因包外实现而长期 `partial` 的问题，重审包会附带直接导入的项目类型和同名 Mapper XML；同一 `file_id` 的新 `reviewed_static` 结论可升级旧 `partial`，但完整结论不会被后续不完整结论降级。最终任务 `25a0be42c66249caa4ab3636c9b3a78c` 已将 54/54 个可审计文件收口，剩余文件为 0，7 个文件明确标为不适用；39 个正式 Finding，61 项独立复核为 52 supported、1 refuted、8 inconclusive。报告仍诚实保持 `partial_report`，原因只剩 2 个未接续基线问题和证据不足/详情版本待复核项。产物保存在 `benchmarks/kernel_quality/results/real-sinkspring-file-complete-2026-09-10/`。
- 修复续跑复核调度只按 `investigation_id` 占位、忽略候选详情版本的问题：只有 `detail_sha256` 与当前详情完全一致的成功复核才会跳过调度；旧版或失败复核会被当前结果槽移除，并保留在父任务历史中供输入真正一致时复用。由此 `investigation-57` 的新版详情在下次续跑会实际进入独立复核，不再永久形成“缺少当前详情版本”缺口。
- 完成度状态区分“工作未执行”和“检查已执行但结论不确定”：失败复核、缺详情、开放调查继续进入 `deferred` 并保持 `partial_report`；具有证据的独立基线终态及成功完成的 `inconclusive` 复核进入 `unresolved`，完整保留局限但不再让报告永久无法结束。`recorded_checks_closed` 仍明确保持 `completeSecurityAudit=false`，不把静态未知项伪装为安全或完整审计。
- 真实续跑任务 `7bc2d9bb398e4798a1e559d26fb8210c` 已在新镜像实际完成：61 项独立复核全部有终态，52 supported、1 refuted、8 inconclusive；39 个正式 Finding 保持不变，文件 remaining/excluded 均为 0，`deferred=0`，10 项证据或部署不确定性完整保留在 `unresolved`。最终完成状态为 `recorded_checks_closed` 且 `completeSecurityAudit=false`，产物保存在 `benchmarks/kernel_quality/results/real-sinkspring-recorded-checks-closed-2026-09-10/`。

