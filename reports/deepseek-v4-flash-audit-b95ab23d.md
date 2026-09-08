# Secval 安全审计报告

- 任务 ID：`b95ab23d16ac43e38dd70523e717ed97`
- 状态：`needs_review`
- 报告收口：`partial_report`

## 执行摘要

完整审阅 p11-orders-api 快照全部2个源文件（auth.py、main.py）。确认对象级授权缺失：AuthMiddleware 仅检查 Authorization 头是否存在（不解析身份），GET /orders/{order_id} 的 get_order 以用户可控 order_id 直接索引 ORDERS 并返回完整订单，未从任何可信身份来源获取当前用户、未校验订单归属，任何携带非空 Authorization 头的用户可枚举 order_id 越权读取其他用户订单及收货地址，构成 IDOR/BOLA（CWE-639），影响为 PII 泄露。主调查与独立基线均支持该假设，已登记为候选发现 detail-1（investigation-1, supported）。KeyError 500 问题因仓库外配置不可见保持 inconclusive。已记录边界 boundary-1 与威胁模型。未做动态验证；仓库外网关身份机制、order_id 取值范围、FastAPI 运行配置为剩余未知项。

## 安全发现

本次没有通过独立静态复核的正式发现。待复核候选见后续章节。

## 待独立复核候选

### 任意已认证用户可越权读取其他用户订单（IDOR）

GET /orders/{order_id} 存在对象级授权缺失：任意携带 Authorization 头的普通用户可通过控制 order_id 越权读取其他用户订单（含收货地址），构成 IDOR/BOLA

- 调查编号：`investigation-1`
- 建议严重性：`high`

## 未决问题

- 网关注入 user_id 会话头的机制与可信性在仓库内无实现证据
- 仓库外 FastAPI 运行配置（debug/异常处理/日志）不可见，影响 KeyError 500 问题定性
- 生产 order_id 取值范围未知，枚举难度未量化
- 未进行动态验证（只读审计）
- 仓库外是否还存在其他认证/授权层不可见

## 覆盖与限制

完整安全审计：`false`

- 仍有未收口的调查、基线问题或候选复核
- 仍有未完成安全审阅声明的文件

静态分析结果均需复核；导出不表示完整覆盖或动态复现。可能包含敏感源码，请勿公开上传。
