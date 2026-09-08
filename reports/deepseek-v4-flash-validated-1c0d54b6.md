# Secval 安全审计报告

- 任务 ID：`1c0d54b6bc8648378ce8b54d9329b66c`
- 状态：`needs_review`
- 报告收口：`partial_report`

## 执行摘要

本次审计经独立静态复核确认 1 条正式安全发现，最高严重性为 high。任意已认证用户可越权读取其他用户订单（IDOR）。每条发现均在下文列出根因位置、攻击路径、复核结论和修复建议；未覆盖范围与静态分析限制见“覆盖与限制”。

## 安全发现

### 1. 任意已认证用户可越权读取其他用户订单（IDOR）

- 严重性：`high`
- 置信度：`high`
- CWE：CWE-639
- 根因位置：`main.py:1`

#### 问题与影响

GET /orders/{order_id} 存在对象级授权缺失：任意携带 Authorization 头的普通用户可通过控制 order_id 越权读取其他用户订单（含收货地址），构成 IDOR/BOLA

#### 根因

get_order 直接以用户可控的 order_id 索引 ORDERS 并返回完整订单，未从任何可信身份来源获取当前用户，也未将订单 owner_user_id 与当前用户比较；AuthMiddleware 仅检查 Authorization 头存在，不建立身份，导致对象级授权控制完全缺失

#### 攻击路径

任何已认证用户可通过路径参数枚举 order_id 越权读取其他用户订单及收货地址（IDOR/BOLA）

#### 独立复核

漏洞假设由证据直接支持。main.py 中唯一路由 get_order(order_id: int, request) 直接以路径参数 order_id 索引 ORDERS 并返回完整订单字典（含 owner_user_id 与收货地址），全程未从任何来源获取当前用户身份，也未将 owner_user_id 与当前用户比较，返回前无对象级授权检查。auth.py 的 AuthMiddleware 仅检查 Authorization 头是否存在，不解析身份、不注入可信 user_id（注释中提到的网关注入身份在快照内无任何消费代码）。因此持有任意非空 Authorization 头即可通过 /orders/{order_id} 读取其他用户订单（如 1002 属 owner_user_id=8），IDOR/BOLA（CWE-639）成立，且影响面（PII 泄露）由源码直接可见。支持结论不依赖 order_id 可枚举性——已知目标订单号即可越权。

#### 修复建议

在 get_order 中先通过可信身份中间件/依赖解析当前用户 user_id，然后校验 order = ORDERS.get(order_id)：若 order 为 None 或 order["owner_user_id"] != current_user_id 则统一返回 404；仅在归属匹配时返回订单。同时将 AuthMiddleware 升级为真正解析并校验 token、向请求上下文注入可信 user_id，缺失/无效令牌返回 401。

## 覆盖与限制

完整安全审计：`false`

- 仍有未收口的调查、基线问题或候选复核
- 仍有未完成安全审阅声明的文件

静态分析结果均需复核；导出不表示完整覆盖或动态复现。可能包含敏感源码，请勿公开上传。
