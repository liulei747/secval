# B腿（安全分析内核）状态说明

日期：2026-09-11
决策：方案 4-B —— 从生产审计路径摘除，标记为研究分支。**代码全部保留。**

## 为什么摘除

B腿的设计目标是用确定性分析替代 LLM 的模式匹配，从而消除过拟合。实施后经代码核对，
它没有达到这个目标，原因有两层。

### 一、数据管线断裂：9 种边没有生产者

分析器消费的边类型与仓库中实际生产的边类型对照：

| EdgeKind | 生产者 |
|---|---|
| `ARGUMENT_TO_PARAMETER` | 无 |
| `RETURNS_TO` | 无 |
| `CHECKS_RESOURCE` | 无 |
| `IN_TRANSACTION` | 无 |
| `READS_RESOURCE` | 无 |
| `WRITES_RESOURCE` | 无 |
| `CAUSES_EFFECT` | 无 |
| `READS_STATE` | 无 |
| `WRITES_STATE` | 无 |
| `FLOWS_TO` | `frontends/security_facts.py` |
| `CALLS` | `facts/adapters.py` |
| `DEFINES_USES` | `facts/adapters.py` |
| `CONFIGURES` / `EXPOSES` / `PROTECTS` / `OVERRIDES` | `frontends/config_facts.py` |

后果：

- `TaintEngine.FLOW_EDGES` 要求 `ARGUMENT_TO_PARAMETER` / `RETURNS_TO` / `DEFINES_USES`。
  其中两种无生产者，且 `FLOWS_TO`（实际生产的一种）不在 `FLOW_EDGES` 内。
- `RaceTransactionEngine` 需要的 4 种边全部无生产者 → `operations: 0`
- `StateMachineEngine` 需要的 3 种边全部无生产者 → `transitions: 0`
- `TaintEngine` 实际靠 `security_facts.py:60-61` 的「同方法 HTTP 入口 → 危险调用」直连工作，
  这是伪数据流，不是跨过程分析。

真实运行指标（`benchmarks/kernel_quality/results/real-sinkspring-threat-model-fixed-2026-09-10`）：

```
StructuralEngine:        operations 0   → candidates 0
StateMachineEngine:      transitions 0  → candidates 0
RaceTransactionEngine:   operations 0   → candidates 0
DependencyReachability:  dependencies 1 → candidates 0
GuardEngine:             effects 2      → candidates 2
ConfigurationEngine:     policies 3     → candidates 3
TaintEngine:             sources 37     → candidates 18
AuthorizationEngine:     operations 2   → candidates 2
```

8 个分析器中 4 个产出为零。

### 二、知识载体与 A 腿相同

`frontends/security_facts.py:22-32` 的 `EFFECTS` 规则表：

```python
("sql", r"\b(?:executeQuery|executeUpdate|createNativeQuery)\s*\(|\$\{"),
("command", r"\b(?:Runtime\.getRuntime\(\)\.exec|ProcessBuilder)\s*\("),
("deserialization", r"\b(?:ObjectInputStream|XMLDecoder)\b|\.readObject\s*\("),
```

与 A 腿 `services/agent_team.py` 的 `_SINK_RULES` 是同一批硬编码字面量。
B腿把知识从 `services/` 搬到了 `frontends/`，形式上是「语义层」，
实质仍是人手按 benchmark 答案枚举的清单——因此不具备泛化能力。

### 三、结论从不进入报告

`kernel_bootstrap.py` 标注 `confirmation_capability: False`，
内核产出的 25 条 `NEEDS_REVIEW` 候选永远不会提升为 Finding。
在 A 腿之后串行运行，只增加墙钟时间。

## 摘除方式

- 配置开关：`SECVAL_KERNEL_DUAL_RUN`（默认 `false`）
- `bootstrap/audit_runtime.py`：仅当开关为 `true` 时才组装 `kernel_runner`
- 报告字段：内核未运行时 `kernelRuntime` 为
  `{"status": "disabled", "note": ...}`，不再呈现为「有确定性兜底」
- 文件标记：见下

## 文件标记约定

被摘除或降级的模块在文件首行加入标记块，便于检索与恢复：

| 标记 | 含义 | 涉及文件 |
|---|---|---|
| `[SECVAL-LEGACY-DISABLED]` | 已从生产路径摘除 | `services/kernel_runtime.py`、`services/kernel_bootstrap.py` |
| `[SECVAL-LEGACY-EXPERIMENTAL]` | 保留在研究路径，不参与正式报告 | `analyzers/`、`facts/`、`semantics/`、`candidates/`、`adjudication/`、`frontends/`、`evaluation/`、`reporting/ledger_report.py` |
| `[SECVAL-LEGACY-SUPERSEDED]` | 被新实现取代 | （暂无） |

检索命令：

```powershell
Get-ChildItem -Recurse -File src/secval -Filter *.py |
  Select-String -Pattern '\[SECVAL-LEGACY-(\w+)\]'
```

## 如何恢复

若要重新评估 B腿：

1. 先补齐断链——`ARGUMENT_TO_PARAMETER` 与 `RETURNS_TO` 的数据源已经存在于
   `CodeCall.argument_count` / `CodeChunk.parameter_count` / `declared_return_full_name`，
   只是没有接入 `FactSnapshotBuilder`。
2. 修复 `kernel_bootstrap.py` 未传 `joern_paths` 的问题。
3. 明确 `FLOWS_TO` 与 `DEFINES_USES` 的语义边界。
4. 设定**关键判据**：补完后跨方法传播路径占比必须 > 0。
   若仍为 0，说明数据流仍是伪的，应保持摘除状态。
5. 决定内核结论是否参与 Finding 提升。若不参与，不应放回生产路径。

## 未删除的内容

本决策不删除任何文件、测试或基准产物。`tests/audit/test_kernel_quality_gates.py`、
`benchmarks/kernel_quality/` 全部保留，冻结基线已按 HEAD 版本修正哈希
（见 `benchmarks/kernel_quality/baseline.json` 的 `revision_reason`）。
