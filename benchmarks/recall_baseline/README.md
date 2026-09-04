# 大召回基线实验

日期：2026-09-04。范围：jeesite-project-api / jeesite-project-main。
只新增实验脚本及结果，没有修改线上参数、索引或模型，不读取 .env 或 API 密钥。

## 方法

1. 调用现有 `/api/search`，Top5 是现有基线：每路15条、RRF取10条精排。
2. 调用同一接口 Top100：每路100条，保留融合后的100条。
3. 按保存的 RRF 分数降序、chunk_id升序恢复精排前顺序，与生产融合规则一致。
4. 对同一候选池分别精排前10、50、100条，检查最终前5。

离线精排复用项目 LocalReranker，BAAI/bge-reranker-base、CPU、256 tokens、batch8。
独立容器不注入密钥，使用已有模型缓存；向量请求由现有 API 处理。
原始响应、完整融合候选、精排排名和耗时保存在 result.json。

## 结果

| 查询 / 检查对象 | 线上Top5 | 大召回RRF排名 | 精排50排名 | 精排100排名 |
| --- | --- | --- | --- | --- |
| 用户登录：FormFilter.executeLogin | 未出现 | 36 | 26 | 37 |
| 用户登录：LoginController.login（页面入口） | 未出现 | 63 | 未入候选 | 4 |
| 用户账号密码登录的入口在哪里：FormFilter.onAccessDenied | 未出现 | 73 | 未入候选 | 41 |
| 文件上传接口在哪里：FileUploadController.uploadFile | 1 | 4 | 3 | 3 |
| 检查登录账号是否重复：UserController.checkLoginCode | 4 | 13 | 7 | 7 |

登录日志查询扩大后仍把日志分页查询放在前面，登录成功日志回调出现在第3、4名。
精确符号查询 FormFilter.executeLogin 在扩大召回与精排50时仍然第1。

关键源码依据：FormFilter.onAccessDenied 调用 executeLogin，executeLogin 委托父类执行；
LoginController.login 是页面入口，不等同于密码认证核心；FileUploadController.uploadFile
调用上传服务；UserController.checkLoginCode 委托账号检查服务；AuthorizingRealm.onLoginSuccess
明确调用 LogUtils.saveLog 写入“系统登录”。这些不是完整相关性标注集合。

## 解释与限制

- 扩大召回确实让 executeLogin 进入候选，但现有精排仍未把它放在前5。
- 扩大精排会引入竞争结果：上传接口与账号检查两个样本排名反而下降。
- 不能把当前失败全部归因于模型本身：输入格式、256-token截断与任务适配仍未分别验证。
- Top100是融合后截取的100条，不是两路最多200条的完整并集。未出现不能证明两路均未召回。
- 每个组合只测一次，固定10→50→100顺序，没有重复、随机顺序或统计置信区间。
  耗时只是本机观察，不是性能SLA；API耗时含已有10条精排，不能与离线精排耗时直接相加。
- 不建议仅凭这些样本把线上直接改成100条精排。下一步宜固定候选池比较输入长度/格式，
  再比较模型；用更广的标注查询集决定生产参数。

## 运行

在仓库根目录 PowerShell 执行（需要现有服务与模型缓存）：

```powershell
docker run --rm --network secval_services --volume "${PWD}:/workspace" --volume secval_huggingface-cache:/models/huggingface --env HF_HOME=/models/huggingface --env HF_HUB_OFFLINE=1 --env PYTHONPATH=/workspace/src --workdir /workspace secval-api:latest python benchmarks/recall_baseline/benchmark.py
```

再次运行会覆盖本目录 result.json，不会修改生产数据。
