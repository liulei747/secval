# SinkSpring 审计系统优化总结

更新时间：2026-09-09  
测试仓库：`sinkspring-bench-eval / sinkspring-bench-eval-v1`  
标准答案：35 个漏洞样本、7 个安全控制样本

## 目标

本轮工作的目标不是单纯增加并行模型数量，而是提高真实漏洞召回率、报告可复核性和投入产出比：

- 完整扫描入口、危险操作和配置；
- 为每条候选建立 Source → Hop → Sink → Control 证据链；
- 区分候选发现、路径验证、独立复核和正式报告；
- 防止证据不足的猜测进入报告；
- 防止已经存在的真实路径因为缺少相邻文件而被降为 `inconclusive`；
- 减少无意义的工具循环、重复复核和大上下文调用。

## 最初基线

初始任务 `6ea9da5f09e9449eacf869f7e31cfeea`：

| 指标 | 结果 |
|---|---:|
| 标准漏洞命中 | 5 / 35 |
| 召回率 | 14.29% |
| 模型调用 | 46 |
| Token | 293,548 |
| 模型任务耗时 | 673.32 秒 |
| 正式发现 | 5 |

主要问题是扫描范围被截断、部分路径没有验证、报告缺少独立复核以及模型反复搜索。

## 已实施改造

### 完整库存与分包

- `list_files` 支持完整分页，不再只读取第一页。
- 入口扫描上限提高，并把所有入口按小包稳定分组。
- 增加确定性危险操作扫描，覆盖 SQL、命令、文件、网络、反序列化、XML、表达式、模板、JNDI、JWT、重定向、HTML 和配置。
- Mapper XML 被允许作为可验证的可执行描述文件读取。
- 路径草图、验证包、验证结果和库存都进入持久化报告。

### 路径验证完整性

- 不再只验证前 62 条路径；任务结束前会补齐孤立的待验证草图。
- 失败的路径包和路径记录可以续跑。
- 88 条候选曾达到 88 条全部验证、0 条验证失败。
- 报告完成状态会明确显示未完成入口、路径包或验证记录。

### V25 存储型 XSS 修复

V25 原来只读取：

- `PageController.java`
- `PageService.java`

因此只能证明 `renderPage` 把 `TITLE/BODY` 拼入 HTML，不能证明内容来自用户输入并被持久化。

改造后自动补读：

- `PageRequest.java`
- `PageRepository.java`

闭合后的路径为：

```text
POST /api/pages
→ @RequestBody PageRequest.title/body
→ PageService.savePage
→ PageRepository.save
→ MERGE INTO page_entries
→ PageRepository.findById
→ PageService.renderPage
→ TITLE/BODY 未编码拼接
→ GET /api/pages/{pageId}, text/html
```

V25 独立复核因此从 `inconclusive` 变为 `supported` 并进入正式报告。

### 独立复核调用收敛

曾出现 70 次模型调用仍没有提交任何复核结果的问题。根因是并行模型包装层没有转发允许工具集合，复核模型看到了不属于本阶段的工具并持续探索。

已改为：

- 程序在模型调用前确定性预取依赖证据；
- 复核模型只允许调用 `submit_independent_review`；
- 拒绝“正在收集”“稍后提交”“待补充”等过程性占位回答；
- 单个复核上下文最多两次格式纠错；
- 完成一条就立即持久化一条。

修复后的 V25 复核首次提交即成功。24 条候选的一轮复核使用 25 次模型调用，全部产生结果。

### 混合证据闭包

没有采用“纯代码必须理解全部业务语义”的方案。当前设计为：

1. 模型发现具有安全语义的候选路径；
2. 程序确定性定位项目内类型、import、DTO、Service、DAO、Repository、Mapper、Validator、Factory 和 Handler；
3. 最多执行三轮本地证据闭包；
4. 搜索结果只作为位置线索，读取源码后才能成为证据；
5. 模型根据闭合证据判断校验、授权、可达性和影响；
6. 找不到的关系记录为明确缺口，不当成安全。

模型证据视图容量从 8,000 字符提高到 32,000 字符。随后又移除了宽泛的全方法名扩展，只递归当前候选路径涉及的包装方法。

### 不可丢弃的确定性候选

模型发现具有随机性，所以新增了程序生成的持久化候选。即使某轮模型没有提到，以下危险点仍必须进入验证：

- `${}`、`executeQuery`；
- `Runtime.exec`、`ProcessBuilder`；
- `Files.readString`、`Files.writeString`；
- HTTP 客户端发送和 URL 连接；
- `ObjectInputStream`、`XMLDecoder`；
- XML 解析；
- SpEL、FreeMarker、JNDI；
- `JWT.decode`；
- HTTP 重定向；
- `text/html` 响应；
- 角色修改；
- Actuator 通配暴露、H2 Console、错误堆栈和硬编码秘密。

候选按危险点所在方法拆分，同一 Mapper 中的多个 statement 不再合并成一条。带 `@PathVariable/@RequestParam ...Id` 的资源入口也会生成对象级授权候选。

## 基准演进

### 第一阶段完整对照

任务链：

- `5dd4e91aa5244f25b4efe03df0c92dea`
- `c384b5fc2b604fa7a49c4f2851a99c69`
- `25824ee8dfe3433ead105b665ea7825f`

结果：

| 指标 | 结果 |
|---|---:|
| 标准漏洞命中 | 14 / 35 |
| 召回率 | 40.00% |
| 代码漏洞召回率 | 43.33% |
| 配置漏洞召回率 | 20.00% |
| 安全控制误报 | 0 / 7 |
| 路径草图/已验证 | 88 / 88 |
| 模型调用 | 90 |
| Token | 621,257 |
| 模型任务耗时 | 1,352.17 秒 |
| 正式发现 | 22 |

### V25 独立复核修复

任务 `2a9737d241294a7f8dba00a44633a7b8`：

| 指标 | 结果 |
|---|---:|
| 独立复核 | 24 |
| supported / refuted / inconclusive / failed | 23 / 1 / 0 / 0 |
| 模型调用 | 25 |
| Token | 220,727 |
| 实际墙钟时间 | 约 7 分 49 秒 |
| 正式发现 | 23 |

### 初版证据闭包

任务 `7be3bed277594fd88a50a835e863451d`：

| 指标 | 结果 |
|---|---:|
| 路径草图/已验证 | 71 / 71 |
| 独立复核 | 28 |
| 正式发现 | 24 |
| 模型调用 | 72 |
| Token | 739,643 |
| 实际墙钟时间 | 约 21 分钟 |
| 严格估算命中 | 约 17 / 35（48.57%） |

该版本补回部分 SQL、命令、路径、JWT、越权和 SSRF，但发现阶段仍有随机漏项。

### 强制候选第一轮

任务 `6adc14f7afe54ee0af6c8fd457bf865d`：

| 指标 | 结果 |
|---|---:|
| 路径草图/已验证 | 120 / 120 |
| 独立复核 | 38 |
| 正式发现 | 34 |
| 模型调用 | 104 |
| Token | 1,201,143 |
| 实际墙钟时间 | 约 30 分钟 |

该轮证明强制候选能提高覆盖，但暴露出闭包污染：一个 XSS 包扩展到 25 个文件，却没有优先读取 `PageService.java`。

### 闭包排序修复后的最终验收

任务 `6e253f09ae7d40e2b599c8a492b4ed4c`：

| 指标 | 结果 |
|---|---:|
| 路径草图/已验证 | 121 / 121 |
| 路径验证 supported | 43 |
| 独立复核 | 43 |
| supported / refuted / inconclusive | 36 / 0 / 7 |
| 正式发现 | 36 |
| 模型调用 | 121 |
| Token | 1,360,846 |
| 模型请求累计耗时 | 3,455.59 秒 |
| 实际墙钟时间 | 约 30 分钟 |

该轮恢复了 V25、对象级越权、开放重定向、XXE、SSTI、JNDI 等发现。Cfg01、Cfg02、Cfg03 在路径验证阶段已判为 `supported`。

## 当前仍未解决的问题

系统目前仍不能宣称完整覆盖标准样本。

### 调用图闭包仍不完整

命令执行路径可以看到私有 `executeCommand → Runtime.exec`，但不能稳定继续连接：

```text
SystemController
→ BackupService
→ NativeProcessHandler.executeShellCommand
→ executeCommand
→ Runtime.exec
```

当前实现通过源码词法搜索包装方法，仍不足以替代带调用点和参数映射的结构化调用图路径。

### Mapper SQL 证据仍会分离

`ProductMapper.xml` 的多个 `${}` statement 已生成独立候选，但验证包仍可能没有稳定同时包含：

- Controller 路由；
- DTO 字段；
- Factory 字段映射；
- Validator 实现；
- Service 调用；
- Mapper XML statement。

因此 V01–V03 仍可能停在 `inconclusive`。

### 报告入口信息没有回写

程序生成的候选最初只有危险方法和待解析入口。即使验证阶段已经找到真实路由，当前结果结构没有把解析出的入口、Source 和完整 Hops 回写到正式发现，所以部分标题仍为“程序生成的闭包候选”。

### 重复候选造成高成本

强制候选和模型候选会描述同一漏洞。当前在独立复核前没有按稳定身份合并，导致同一路径被重复验证和复核。

### 单条结构错误仍可能漏报

角色修改候选曾因模型结构输出错误留下失败记录。路径验证需要像独立复核一样支持短上下文修复和失败包续跑。

### 配置发现与正式报告存在断层

Actuator、H2 Console 和 Stacktrace 已在路径验证阶段确认，但没有全部稳定进入最终报告。配置候选需要独立的报告转换路径，不能依赖普通 HTTP 攻击路径的字段。

## 下一阶段实施顺序

### P0：结构化路径中间表示

新增统一路径对象：

```json
{
  "candidate_type": "command_injection",
  "entry": {"route": "POST /api/system/backup", "method": "SystemController.createBackup"},
  "source": {"symbol": "BackupRequestDTO.backupPath"},
  "hops": [
    {"from": "SystemController.createBackup", "to": "BackupService.createBackup", "mapping": "request.backupPath -> backupPath"},
    {"from": "BackupService.createBackup", "to": "NativeProcessHandler.executeShellCommand", "mapping": "command -> command"}
  ],
  "sink": {"method": "NativeProcessHandler.executeCommand", "operation": "Runtime.exec"},
  "controls": [],
  "missing_edges": []
}
```

程序负责证明节点和调用边；模型负责判断映射、控制有效性和实际影响。

### P0：按候选隔离证据

- 每个候选维护独立证据集合；
- 只读取调用图上的定义、调用者、被调用者和控制；
- 禁止 SQL 文件进入 XSS 包等跨类型污染；
- 定义文件优先于引用文件；
- 超过容量时按路径节点优先级截断，而不是按插入顺序截断。

### P0：验证前去重

使用以下稳定键合并程序候选和模型候选：

```text
漏洞类型 + 入口路由/入口方法 + Sink 方法或 Mapper statement + 根因位置
```

合并证据和缺口后只验证、复核一次。安全控制候选保留独立身份。

### P1：验证结果回写路径

路径验证输出需要包含：

- `resolved_entry`
- `resolved_source`
- `resolved_hops`
- `resolved_sink`
- `resolved_controls`

Finding Builder 使用解析后的真实路径生成标题、摘要、修复建议和代码位置。

### P1：失败恢复

- 路径验证结构错误执行一次短 JSON 修复；
- 网络错误使用新上下文重试一次；
- 失败记录不占位，续跑时只重做失败路径；
- 所有候选必须具有 supported、refuted、inconclusive 或明确 failed 状态。

### P1：配置专用通道

- 将 YAML/Properties 解析为扁平配置树；
- 保存配置键、值、profile、来源文件和环境覆盖关系；
- 静态危险值可以形成带部署前提的配置发现；
- 运行时 profile 和网络暴露作为严重性、可达性限制，而不是抹去静态缺陷；
- 配置结果直接进入独立复核和正式报告。

### P2：成本目标

下一阶段验收目标：

| 指标 | 目标 |
|---|---:|
| 标准漏洞召回率 | ≥ 85%，随后提升到 100% |
| 7 个安全控制误报 | 0 |
| 重复正式发现 | 0 |
| 路径验证完成率 | 100% |
| 模型调用 | ≤ 70 |
| Token | ≤ 700,000 |
| 实际墙钟时间 | ≤ 15 分钟 |

在没有达到以上指标前，不应把系统描述为“全面覆盖完成”或“达到 Codex Security 效果”。

## 相关报告

- `reports/sinkspring-comparison-25824ee8.md`
- `reports/sinkspring-report-2a9737d2.md`
- `reports/sinkspring-report-7be3bed2.md`
- `reports/sinkspring-report-6adc14f7.md`
- `reports/sinkspring-report-6e253f09.md`
- `reports/v25-evidence-chain-25824ee8.md`

