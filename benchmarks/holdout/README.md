# 留出集（Hold-out Set）

## 为什么需要这个

Secval 之前的验收只用 SinkSpring 一个项目，而代码里的规则表（`_SINK_RULES` 等）
是对着它的答案调整出来的。结果是 SinkSpring 召回率 88.57%，但这个数字**不能代表
泛化能力**——它是训练集上的成绩。

留出集的作用：**在从未参与规则调整的项目上测一次真实召回**。这是唯一能证伪
"我们的规则是否过拟合"的手段。

## 使用纪律

1. **规则只在 SinkSpring 上调整**；本集不得用于调参。
2. 本集**只运行一次**得出基线；改造后再运行一次做对比。
3. 若因本集结果回头修改规则，必须重新冻结并公开披露。
4. `expected/*.json` 内容**不得进入模型上下文**；评分必须离线进行。

## 仓库组成

| ID | 语言 | 框架 | Commit | 用途 |
|---|---|---|---|---|
| `petclinic` | Java | Spring | `818c4136ea97` | **误报控制**：官方示例，无已知漏洞 |
| `nodegoat` | JavaScript | Express | `c5cb68a7084e` | **召回率**：OWASP 故意植入漏洞 |
| `flask-src` | Python | Flask | `d73fa1cdcbd8` | **边界理解**：成熟框架，不应报框架内部机制 |

三个仓库刻意选了不同语言与框架，避免任何一个框架的专有模式主导结果。

## 真值来源

`nodegoat` 的漏洞来自**源码内注释**，可靠性高：项目用 `// Fix for A1 ...`
注释块标出修复方案，而被注释掉的正是修复代码本身，因此可确认漏洞处于存活状态。

已确认的 5 条（对照 `expected/nodegoat.json`）：

| ID | 类型 | 位置 | 证据 |
|---|---|---|---|
| NG01 | code_injection | `app/routes/contributions.js:31` | `eval(req.body.preTax)` |
| NG02 | open_redirect | `app/routes/index.js:71` | `res.redirect(req.query.url)` |
| NG03 | object_level_authorization | `app/routes/allocations.js:13` | userId 取自 params 而非 session |
| NG04 | nosql_injection | `app/data/allocations-dao.js:67` | threshold 未转义进入查询 |
| NG05 | redos | `app/routes/profile.js:53` | `/([0-9]+)+\#/` 嵌套量词 |

`petclinic` 与 `flask-src` 不计算召回率，只计算误报。

## 运行

```powershell
# 查看仓库状态
.\.venv\Scripts\python.exe -m benchmarks.holdout.run_holdout --list

# 对某个仓库跑审计后评分
.\.venv\Scripts\python.exe -m benchmarks.holdout.run_holdout --repo nodegoat --report <报告.json>
```

真实审计需要已配置模型 API。评分本身是离线纯计算的。

## 结果解读

- **`nodegoat` 召回率**：这是可以对外声明的泛化能力数字。
- **`petclinic` / `flask-src` 的高危发现数**：应为 0 或极少。若出现大量
  `critical`/`high`，说明规则在把正常代码或框架机制误判为漏洞。
- **`findings_outside_expected`**：命中真值之外的发现数，需人工抽查是否为误报。

## 与 SinkSpring 的关系

两个数据集用途不同，不要混用：

| | SinkSpring | 留出集 |
|---|---|---|
| 角色 | 训练/调参集 | 泛化验收集 |
| 允许调参 | 是 | **否** |
| 数字含义 | 拟合程度 | 泛化能力 |

改造后的对比报告中，**留出集数字才是主指标**；SinkSpring 数字只用于确认没有破坏原有能力。
