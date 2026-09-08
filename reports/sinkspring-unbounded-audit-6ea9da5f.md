# Secval 安全审计报告

- 任务 ID：`6ea9da5f09e9449eacf869f7e31cfeea`
- 状态：`needs_review`
- 报告收口：`partial_report`

## 执行摘要

本次审计经独立静态复核确认 5 条正式安全发现，最高严重性为 high。ssrf：GET /api/integrations/preview?location=；ssrf：POST /api/integrations/updates；expression_injection：POST /api/tools/calculate；jndi_injection：GET /api/tools/directory?name={name}；xss：GET /api/pages/search?query={用户输入}。每条发现均在下文列出根因位置、攻击路径、复核结论和修复建议；未覆盖范围与静态分析限制见“覆盖与限制”。

## 安全发现

### 1. ssrf：GET /api/integrations/preview?location=

- 严重性：`medium`
- 置信度：`high`
- CWE：CWE-918
- 根因位置：`src/main/java/com/sinkspring/bench/controller/IntegrationController.java:1`

#### 问题与影响

location参数未经校验流入远程资源获取逻辑构成SSRF

#### 根因

控制器将location参数直接传入loadPreview，后者以URI.create(location)构造HttpGet请求并发送，无协议或主机校验，SSRF路径完整。

#### 攻击路径

location参数未经校验流入远程资源获取逻辑构成SSRF

#### 独立复核

源码证据完整证明SSRF假设。IntegrationController.preview()（file:fcbe...:0:1521）以@RequestParam String location直接接收攻击者可控输入，无任何校验即调用resourceSyncService.loadPreview(location)；ResourceSyncService.loadPreview()（file:a531...:0:2905）以URI.create(location)构造HttpRequest并执行出站GET请求，无协议/主机/内网地址过滤，响应体原样返回给调用者。输入到敏感出站操作的路径完整且无中间防护，SSRF漏洞假设成立。

#### 修复建议

在GET /api/integrations/preview?location=到攻击者可控URL的出站GET请求（可访问内网与云元数据）之间实施并集中复用控制器无校验且无协议/主机白名单证据。

### 2. ssrf：POST /api/integrations/updates

- 严重性：`medium`
- 置信度：`high`
- CWE：CWE-918
- 根因位置：`src/main/java/com/sinkspring/bench/controller/IntegrationController.java:1`

#### 问题与影响

RemoteRequest目标地址字段直接驱动出站请求构成SSRF

#### 根因

sendUpdate接收RemoteRequest请求体，deliverUpdate直接取callback字段构建URL并发起POST请求，payload作为内容，无目标地址校验，SSRF路径完整。

#### 攻击路径

RemoteRequest目标地址字段直接驱动出站请求构成SSRF

#### 独立复核

源码证据直接证明SSRF数据路径与控制失效：IntegrationController.sendUpdate通过@RequestBody接收攻击者可控的RemoteRequest并调用resourceSyncService.deliverUpdate(request)；deliverUpdate对request.getCallback()执行URI.create(...).toURL()并openConnection发起出站POST请求（payload写入输出流），全程无scheme限制、无目标白名单、无任何地址校验，RemoteRequest DTO（location/callback/payload）亦无验证注解。入口（POST /api/integrations/updates）→DTO字段→出站请求路径完整。端点仅向调用方回传响应状态码，属盲SSRF（内网探测/状态码观察），medium影响评级合理。漏洞假设成立。

#### 修复建议

在POST /api/integrations/updates到攻击者指定端点的出站请求（内网探测/元数据访问）之间实施并集中复用控制器未校验请求体字段且无目标白名单证据。

### 3. expression_injection：POST /api/tools/calculate

- 严重性：`high`
- 置信度：`high`
- CWE：CWE-917
- 根因位置：`src/main/java/com/sinkspring/bench/controller/OperationsToolController.java:1`

#### 问题与影响

若 formula 被 SpEL/EL 类引擎直接求值，攻击者可注入表达式实现 RCE 或资源耗尽

#### 根因

calculate 将攻击者可控 formula 直接交给 SpelExpressionParser 在 StandardEvaluationContext 中求值，无过滤或沙箱，表达式注入可达任意方法调用。

#### 攻击路径

若 formula 被 SpEL/EL 类引擎直接求值，攻击者可注入表达式实现 RCE 或资源耗尽

#### 独立复核

源码证据直接证明该漏洞假设成立：OperationsToolController.calculate 将请求体 ToolRequest.getFormula() 原样传入 OperationsToolService.calculate，而该服务方法使用 SpelExpressionParser.parseExpression(formula).getValue(new StandardEvaluationContext()) 直接求值，未做任何过滤、白名单或沙箱（未使用 SimpleEvaluationContext，也未禁用类型引用/构造器/静态方法调用）。StandardEvaluationContext 允许 T(...) 类型引用、静态方法调用与构造器调用，攻击者可控表达式文本经公开 POST /api/tools/calculate 端点可达该敏感求值，满足表达式注入→任意方法调用（如 T(java.lang.Runtime).getRuntime().exec(...)）或资源耗尽的前提。证据中的代码路径完整（controller→service→SpEL 求值），无反向防护证据。calculatePreset 使用 SimpleEvaluationContext 不构成对本端点的反证。

#### 修复建议

在POST /api/tools/calculate到表达式求值执行（SpEL/EL 类引擎求值可能达任意代码执行）之间实施并集中复用未知，需确认求值器类型、黑名单过滤与沙箱。

### 4. jndi_injection：GET /api/tools/directory?name={name}

- 严重性：`high`
- 置信度：`high`
- CWE：CWE-74
- 根因位置：`src/main/java/com/sinkspring/bench/controller/OperationsToolController.java:1`

#### 问题与影响

若攻击者可控的 name 被拼入 JNDI 查询串或作为完整 URL 传入 lookup，可触发 JNDI 注入并可能导致远程类加载或 LDAP 攻击面利用

#### 根因

Controller将GET参数name直接传入operationsToolService.lookupDirectory；Service内new InitialContext().lookup(name)未做任何协议白名单或格式校验，name完全可控直达JNDI解析sink，数据流与控制失效均有源码证据。

#### 攻击路径

若攻击者可控的 name 被拼入 JNDI 查询串或作为完整 URL 传入 lookup，可触发 JNDI 注入并可能导致远程类加载或 LDAP 攻击面利用

#### 独立复核

漏洞假设获源码证据支持。完整数据流均可见于所给两份证据：(1) OperationsToolController.directoryEntry 将 GET /api/tools/directory 的 @RequestParam String name 未经任何变换直接传入 operationsToolService.lookupDirectory(name)；(2) OperationsToolService.lookupDirectory 内直接执行 new InitialContext().lookup(name)，无协议白名单、格式校验或任何过滤，方法声明抛出 NamingException。攻击者可控的 name 作为完整目标直达 javax.naming.InitialContext.lookup 这一 JNDI 注入 sink，控制失效与路径可达性均有直接源码证明。JNDI lookup 接受 ldap://、rmi:// 等 URL 型参数，注入前提成立；"远程类加载/LDAP 攻击面"为条件性影响表述，与注入本身成立不冲突。候选详情中"Service 实现未读"的说法不准确——实现已在证据中完整可见且无校验，反而比候选所述更直接。

#### 修复建议

在GET /api/tools/directory?name={name}到javax.naming.InitialContext 或目录服务的 JNDI 解析（方法已声明抛出 NamingException）之间实施并集中复用未知，需确认 lookupDirectory 是否对 name 做协议白名单或格式限制。

### 5. xss：GET /api/pages/search?query={用户输入}

- 严重性：`medium`
- 置信度：`high`
- CWE：CWE-79
- 根因位置：`src/main/java/com/sinkspring/bench/controller/PageController.java:1`

#### 问题与影响

若buildSearchPage将query原样拼接进HTML页面并返回text/html，则构成反射型XSS。

#### 根因

PageService.buildSearchPage直接将query拼接进HTML且未转义，PageController以text/html返回，构成反射型XSS。

#### 攻击路径

若buildSearchPage将query原样拼接进HTML页面并返回text/html，则构成反射型XSS。

#### 独立复核

源码直接证明漏洞假设成立：PageController.search 以 produces=MediaType.TEXT_HTML_VALUE 暴露 GET /api/pages/search，将 @RequestParam String query 原样传给 pageService.buildSearchPage(query)；PageService.buildSearchPage 将 query 直接拼接进 "<html>...Results for " + query + "</p></body></html>"，未做任何 HTML 转义。同文件 buildSearchText 使用 HtmlUtils.htmlEscape 转义，反衬 buildSearchPage 路径未转义。攻击者可控输入被未转义反射进 text/html 响应体，构成反射型 XSS（CWE-79），条件前提"原样拼接+返回text/html"均被源码证实。

#### 修复建议

在GET /api/pages/search?query={用户输入}到浏览器端未转义HTML/脚本执行之间实施并集中复用未知——buildSearchPage是否对query做HTML实体转义无证据。

## 待独立复核候选

### jwt_verification_bypass：GET /api/accounts/admin/export（Authorization: Bearer JWT）

若JWT使用弱密钥、允许无签名算法或未校验过期，攻击者可自签admin角色令牌绕过认证

- 调查编号：`investigation-1`
- 建议严重性：`high`

### object_level_authorization：GET /api/pages/{pageId}

若renderPage不校验访问者与页面属主关系，任意pageId枚举即可泄露他人页面内容构成IDOR。

- 调查编号：`investigation-6`
- 建议严重性：`medium`

### unknown：GET /api/navigation/section?name={任意字符串}

name 参数无法影响重定向目标内容，仅能命中预置键，无开放重定向或注入路径

- 调查编号：`investigation-8`
- 建议严重性：`medium`

## 未决问题

- 最终发现仅包含独立复核支持的候选；覆盖限制见确定性报告。

## 覆盖与限制

完整安全审计：`false`

- 仍有未收口的调查、基线问题或候选复核
- 仍有未完成安全审阅声明的文件
- 独立基线尚未提交调查问题
- 尚未建立结构化威胁模型

静态分析结果均需复核；导出不表示完整覆盖或动态复现。可能包含敏感源码，请勿公开上传。
