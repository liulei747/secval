# Secval 安全审计报告

- 任务 ID：`6adc14f7afe54ee0af6c8fd457bf865d`
- 状态：`needs_review`
- 报告收口：`partial_report`

## 执行摘要

本次审计经独立静态复核确认 34 条正式安全发现，最高严重性为 high。arbitrary_file_write：待由调用者闭包解析的入口；path_traversal：待由调用者闭包解析的入口；jndi_injection：GET /api/tools/directory?name=；sql_injection：待由调用者闭包解析的入口；sql_injection：待由调用者闭包解析的入口；另有 29 条。每条发现均在下文列出根因位置、攻击路径、复核结论和修复建议；未覆盖范围与静态分析限制见“覆盖与限制”。

## 安全发现

### 1. arbitrary_file_write：待由调用者闭包解析的入口

- 严重性：`high`
- 置信度：`high`
- CWE：CWE-73
- 根因位置：`src/main/java/com/sinkspring/bench/service/DocumentService.java:1`

#### 问题与影响

外部输入可能到达 Files.writeString 且缺少规范化后目录边界检查

#### 根因

DocumentController的POST /api/documents/content将外部可控制DocumentRequest.path传入storeDocument，resolve后直接Files.writeString且无normalize/startsWith边界检查，可经绝对路径或..实现任意文件写

#### 攻击路径

外部输入可能到达 Files.writeString 且缺少规范化后目录边界检查

#### 独立复核

源码证据支持该漏洞假设。实际入口由 DocumentController 证明：@PostMapping("/content") 的 putContent 将请求体反序列化为 DocumentRequest（path、content 均为外部可控 String），直接调用 DocumentService.storeDocument。storeDocument 中 Path document = documentRoot.resolve(request.getPath()) 后无任何 normalize/toRealPath/startsWith 边界检查即调用 Files.writeString（CREATE+TRUNCATE_EXISTING）。Path.resolve 对绝对路径（如 /etc/...）直接返回该路径，含 .. 的相对路径在文件系统解析后同样可越出 documentRoot，且缺失父目录会被 createDirectories 创建；content 亦可由攻击者控制，构成任意文件写（CWE-73）。同文件 loadPublishedDocument 展示了 normalize+startsWith 的正确防护模式但未在 storeDocument 路径复用，进一步印证该路径控制缺失。HTTP 入口（POST /api/documents/content）在证据中无认证或过滤层，可直接到达。

#### 修复建议

在待由调用者闭包解析的入口到src/main/java/com/sinkspring/bench/service/DocumentService.java 中的 Files.writeString之间实施并集中复用规范化后目录边界检查。

### 2. path_traversal：待由调用者闭包解析的入口

- 严重性：`medium`
- 置信度：`high`
- CWE：CWE-22
- 根因位置：`src/main/java/com/sinkspring/bench/service/DocumentService.java:1`

#### 问题与影响

外部输入可能到达 Files.readString 且缺少规范化后目录边界检查

#### 根因

DocumentController.getContent将外部name参数传入loadDocument，后者未做规范化或边界检查即resolve并Files.readString。

#### 攻击路径

外部输入可能到达 Files.readString 且缺少规范化后目录边界检查

#### 独立复核

支持漏洞假设。证据链完整可复核：(1) DocumentController.getContent 以 @RequestParam String name 接收外部 HTTP 输入并直接调用 documentService.loadDocument(name)；(2) DocumentService.loadDocument 仅执行 documentRoot.resolve(name) 后直接 Files.readString(document, UTF_8)，既无 .normalize() 也无 startsWith(root) 边界检查；(3) Path.resolve 对绝对路径直接返回、对 "../" 相对路径不做规范化，因此 name=/etc/passwd 或 name=../../<路径> 均可解析到 documentRoot 之外并触发 Files.readString 读取。被引用的调用链（controller→service→sink）与"缺少规范化后目录边界检查"均由源码直接证明。

#### 修复建议

在待由调用者闭包解析的入口到src/main/java/com/sinkspring/bench/service/DocumentService.java 中的 Files.readString之间实施并集中复用规范化后目录边界检查。

### 3. jndi_injection：GET /api/tools/directory?name=

- 严重性：`high`
- 置信度：`high`
- CWE：CWE-74
- 根因位置：`src/main/java/com/sinkspring/bench/controller/OperationsToolController.java:1`

#### 问题与影响

name直接拼入JNDI名称并lookup，攻击者可指向恶意LDAP/RMI服务器触发远程类加载。

#### 根因

证据完整证明GET /api/tools/directory的RequestParam name直接传入lookupDirectory(name)，service使用new InitialContext().lookup(name)无任何协议、主机或名称白名单限制，外部可控JNDI名称可达lookup sink。

#### 攻击路径

name直接拼入JNDI名称并lookup，攻击者可指向恶意LDAP/RMI服务器触发远程类加载。

#### 独立复核

源码证据证实漏洞假设的数据路径：OperationsToolController 的 GET /api/tools/directory 以 @RequestParam String name 接收用户输入（无任何校验），直接调用 operationsToolService.lookupDirectory(name)；OperationsToolService.lookupDirectory 执行 new InitialContext().lookup(name) 并将结果 String.valueOf 返回。name 未经过任何协议、主机或名称白名单限制即到达 JNDI lookup 敏感操作，且代码路径内未见有效防护。边界跨越（HTTP GET 未授权请求参数）与输入到敏感操作的传递均由所给源码直接证明。'name直接拼入JNDI名称并lookup' 成立；攻击者可令 JNDI 名称指向任意 ldap://rmi:// 地址导致服务端发起外部 JNDI 解析。'远程类加载'为该 sink 的典型影响，但其实际可利用性依赖运行环境（JDK 版本及 trustURLCodebase 等属性），该部分未在证据中证明，仅作为限制记录，不否定注入漏洞本身。

#### 修复建议

在GET /api/tools/directory?name=到JNDI InitialContext.lookup之间实施并集中复用未观察到名称格式或协议白名单校验。

### 4. sql_injection：待由调用者闭包解析的入口

- 严重性：`high`
- 置信度：`high`
- CWE：CWE-89
- 根因位置：`src/main/java/com/sinkspring/bench/dao/LegacyOrderDAO.java:1`

#### 问题与影响

外部输入可能到达 executeQuery 且缺少参数化SQL

#### 根因

OrderController的orderId经OrderService直达findOrderById，拼接SQL并执行，无参数化

#### 攻击路径

外部输入可能到达 executeQuery 且缺少参数化SQL

#### 独立复核

证据完整证实漏洞假设。调用链闭合：OrderController 的三个端点（GET /api/orders/{orderId} 的 @PathVariable、GET /api/orders/legacy/view 的 @RequestParam、POST /api/orders/process 的 @RequestBody）均接收外部可控 orderId；OrderService.getOrderDetails/handleLegacyRequest/processOrderAction 将 context 传入 LegacyOrderDAO.findOrderById/executeOrderQuery；DAO 中将 orderId 直接字符串拼接为 "SELECT * FROM orders WHERE order_id = '" + orderId + "'"，并由私有 executeQuery 通过 Statement.executeQuery(sql) 执行（非 PreparedStatement，无参数化）。该路径中未发现任何校验、过滤或转义环节，外部输入可达非参数化 SQL 执行点，SQL 注入（CWE-89）假设成立。

#### 修复建议

在待由调用者闭包解析的入口到src/main/java/com/sinkspring/bench/dao/LegacyOrderDAO.java 中的 executeQuery之间实施并集中复用参数化SQL。

### 5. sql_injection：待由调用者闭包解析的入口

- 严重性：`high`
- 置信度：`high`
- CWE：CWE-89
- 根因位置：`src/main/java/com/sinkspring/bench/dao/LegacyOrderDAO.java:1`

#### 问题与影响

外部输入可能到达 executeQuery 且缺少参数化SQL

#### 根因

OrderController的processOrder经OrderService.processOrderAction直达executeOrderQuery，拼接SQL执行，无参数化

#### 攻击路径

外部输入可能到达 executeQuery 且缺少参数化SQL

#### 独立复核

证据链完整支持漏洞假设。LegacyOrderDAO.findOrderById 与 executeOrderQuery 均以字符串拼接（"SELECT * FROM orders WHERE order_id = '" + orderId + "'"）构造 SQL 并传入私有 executeQuery，后者用 java.sql.Statement.executeQuery(sql) 执行，全程无 PreparedStatement 或参数绑定。外部输入路径明确：OrderController 的 POST /api/orders/process（@RequestBody orderId，经 processOrderAction→executeOrderQuery）、GET /api/orders/{orderId}（经 getOrderDetails→findOrderById）、GET /api/orders/legacy/view（经 handleLegacyRequest→findOrderById）均由 HTTP 输入直接流入拼接 SQL。所给证据中无任何校验/过滤/白名单环节，OrderContext 为普通 DTO。CWE-89 拼接式 SQL 注入根因、可达性均获源码证明。

#### 修复建议

在待由调用者闭包解析的入口到src/main/java/com/sinkspring/bench/dao/LegacyOrderDAO.java 中的 executeQuery之间实施并集中复用参数化SQL。

### 6. sql_injection：待由调用者闭包解析的入口

- 严重性：`high`
- 置信度：`high`
- CWE：CWE-89
- 根因位置：`src/main/java/com/sinkspring/bench/dao/LegacyOrderDAO.java:1`

#### 问题与影响

外部输入可能到达 executeQuery 且缺少参数化SQL

#### 根因

私有executeQuery接收拼接SQL执行Statement.executeQuery，调用链已由findOrderById/executeOrderQuery覆盖且无参数化

#### 攻击路径

外部输入可能到达 executeQuery 且缺少参数化SQL

#### 独立复核

漏洞假设成立。证据链完整：OrderController 的 @GetMapping("/{orderId}")/@PostMapping("/process")/@GetMapping("/legacy/view") 接收外部 HTTP 输入（path variable 或 request body）写入 OrderRequestDTO；OrderService.getOrderDetails/handleLegacyRequest/processOrderAction 将 orderId 传入 OrderContext（OrderContextFactory.buildContext 直接复制 requestDTO.getOrderId()，无任何校验）；LegacyOrderDAO.findOrderById/executeOrderQuery 用字符串拼接构造 "SELECT/UPDATE ... WHERE order_id = '" + orderId + "'" 并交给私有 executeQuery；executeQuery 使用 java.sql.Statement.executeQuery(sql) 非参数化执行。整条路径上未见任何输入过滤、白名单或参数绑定，SQL 注入（CWE-89）控制失效由源码直接证明，未发现反证。

#### 修复建议

在待由调用者闭包解析的入口到src/main/java/com/sinkspring/bench/dao/LegacyOrderDAO.java 中的 executeQuery之间实施并集中复用参数化SQL。

### 7. expression_injection：待由调用者闭包解析的入口

- 严重性：`high`
- 置信度：`high`
- CWE：CWE-917
- 根因位置：`src/main/java/com/sinkspring/bench/service/OperationsToolService.java:1`

#### 问题与影响

外部输入可能到达 parseExpression 且缺少固定表达式或受限求值上下文

#### 根因

Controller将用户formula直接传入calculate，SpEL StandardEvaluationContext无沙箱解析执行，表达式注入成立。

#### 攻击路径

外部输入可能到达 parseExpression 且缺少固定表达式或受限求值上下文

#### 独立复核

漏洞假设成立。证据链完整：OperationsToolController 的 @PostMapping("/calculate") 直接以 @RequestBody ToolRequest 接收用户输入，调用 operationsToolService.calculate(request.getFormula(), request.getValues())（controller 证据 1815 行块）；OperationsToolService.calculate 将 formula 原样传入 parser.parseExpression(formula)，并使用 StandardEvaluationContext（非受限求值上下文）执行 getValue(context)（service 证据 2719 行块）。ToolRequest 的 formula 字段为无约束字符串（DTO 证据 289 行块）。外部 HTTP 输入可到达 parseExpression 且无固定表达式白名单、无输入校验、无受限求值上下文（对比同文件 calculatePreset 使用 SimpleEvaluationContext 与固定公式映射，证明该路径缺少等效防护）。StandardEvaluationContext 允许类型引用与方法调用，构成 SpEL 表达式注入（CWE-917），可造成任意代码执行，high 评级合理。

#### 修复建议

在待由调用者闭包解析的入口到src/main/java/com/sinkspring/bench/service/OperationsToolService.java 中的 parseExpression之间实施并集中复用固定表达式或受限求值上下文。

### 8. expression_injection：POST /api/tools/calculate

- 严重性：`high`
- 置信度：`high`
- CWE：CWE-917
- 根因位置：`src/main/java/com/sinkspring/bench/service/OperationsToolService.java:1`

#### 问题与影响

用户提交的formula直接进入表达式引擎求值，可执行任意表达式导致RCE，需确认引擎类型。

#### 根因

用户formula经POST /api/tools/calculate直达calculate，SpEL标准上下文直接解析求值，无沙箱限制，可RCE。

#### 攻击路径

用户提交的formula直接进入表达式引擎求值，可执行任意表达式导致RCE，需确认引擎类型。

#### 独立复核

引擎类型已由源码确认为Spring Expression Language（SpEL）：OperationsToolService.java导入SpelExpressionParser，calculate()对用户formula调用parser.parseExpression(formula).getValue(context)，context为StandardEvaluationContext（非受限上下文）。控制器OperationsToolController的POST /api/tools/calculate直接以@RequestBody ToolRequest.getFormula()传入，无任何校验、白名单或沙箱；StandardEvaluationContext支持T()类型引用与静态方法调用，可实现表达式注入乃至RCE。路径中未发现任何防护（无沙箱、无输入过滤）；calculatePreset使用的SimpleEvaluationContext仅作用于预设路径，不影响/calculate。综上，漏洞假设由源码证据支持。

#### 修复建议

在POST /api/tools/calculate到表达式求值（SpEL/OGNL/MVEL等）之间实施并集中复用未观察到公式来源限制或沙箱配置。

### 9. ssrf：待由调用者闭包解析的入口

- 严重性：`medium`
- 置信度：`high`
- CWE：CWE-918
- 根因位置：`src/main/java/com/sinkspring/bench/service/ResourceSyncService.java:1`

#### 问题与影响

外部输入可能到达 httpClient.send 且缺少目标协议和地址白名单

#### 根因

IntegrationController.preview 将 @RequestParam location 直接传入 loadPreview，URI.create(location) 后由 httpClient.send 请求，无协议或地址白名单校验。

#### 攻击路径

外部输入可能到达 httpClient.send 且缺少目标协议和地址白名单

#### 独立复核

漏洞假设成立。证据显示 IntegrationController.preview（@GetMapping("/api/integrations/preview")）将 @RequestParam String location 直接传入 ResourceSyncService.loadPreview(location)；loadPreview 中 HttpRequest.newBuilder(URI.create(location)).GET() 后调用 httpClient.send，全程无协议或地址白名单校验。唯一白名单（catalogLocations map）只存在于 loadCatalog（受控于 @PathVariable catalog），与 loadPreview 路径无关；RemoteRequest/location 等其他字段与 httpClient.send 无关。故外部可控输入可到达 httpClient.send 且目标协议/地址不受限，构成 SSRF（CWE-918）前提。

#### 修复建议

在待由调用者闭包解析的入口到src/main/java/com/sinkspring/bench/service/ResourceSyncService.java 中的 httpClient.send之间实施并集中复用目标协议和地址白名单。

### 10. ssrf：待由调用者闭包解析的入口

- 严重性：`medium`
- 置信度：`high`
- CWE：CWE-918
- 根因位置：`src/main/java/com/sinkspring/bench/service/ResourceSyncService.java:1`

#### 问题与影响

外部输入可能到达 getResponseCode 且缺少目标协议和地址白名单

#### 根因

IntegrationController.sendUpdate 将 @RequestBody RemoteRequest 传入 deliverUpdate，callback 直接用于 URI.create 和 openConnection，无目标限制。

#### 攻击路径

外部输入可能到达 getResponseCode 且缺少目标协议和地址白名单

#### 独立复核

证据支持该漏洞假设。数据流完整且直接可见：IntegrationController.sendUpdate 是 POST /api/integrations/updates 端点，以 @RequestBody 接收 RemoteRequest（其 callback 字段无任何约束，完全由请求体控制），并调用 ResourceSyncService.deliverUpdate(request)。deliverUpdate 中 request.getCallback() 未经任何协议/地址校验即用于 URI.create(...).toURL().openConnection()，随后写入请求体并调用 connection.getResponseCode()。源码中唯一的白名单是 catalogLocations（仅用于 loadCatalog），deliverUpdate/refreshLegacyIndex 路径均无目标校验。因此"外部输入到达 getResponseCode 且缺少目标协议和地址白名单"由给定源码直接证明（CWE-918 SSRF：可诱使服务器向任意内部 HTTP 目标发起 POST 并返回状态码）。

#### 修复建议

在待由调用者闭包解析的入口到src/main/java/com/sinkspring/bench/service/ResourceSyncService.java 中的 getResponseCode之间实施并集中复用目标协议和地址白名单。

### 11. open_redirect：待由调用者闭包解析的入口

- 严重性：`medium`
- 置信度：`high`
- CWE：CWE-601
- 根因位置：`src/main/java/com/sinkspring/bench/controller/NavigationController.java:1`

#### 问题与影响

外部输入可能到达 .location( 且缺少站内目标白名单

#### 根因

NavigationController.continueTo 将 @RequestParam next 直接传入 URI.create 并用于 302 Location，无任何站内白名单或校验，外部输入可控制任意跳转。

#### 攻击路径

外部输入可能到达 .location( 且缺少站内目标白名单

#### 独立复核

证据文件完整包含 NavigationController 两个端点的全部方法体。continueTo(@RequestParam String next) 将 HTTP 请求参数 next 直接传入 URI.create(next)，返回值用于 ResponseEntity.status(302).location(...)，方法内不存在任何白名单、scheme/host 校验或前缀限制；同类中定义的 destinations 白名单仅被另一端点 section() 使用，未应用于 continueTo。因此“外部输入可能到达 .location( 且缺少站内目标白名单”这一漏洞假设在源码层面成立：输入边界（@RequestParam 绑定 HTTP 参数）→ URI.create → 302 Location 的数据流完整可见，未发现有效防护，构成 open redirect（CWE-601，medium）。

#### 修复建议

在待由调用者闭包解析的入口到src/main/java/com/sinkspring/bench/controller/NavigationController.java 中的 .location(之间实施并集中复用站内目标白名单。

### 12. xxe：待由调用者闭包解析的入口

- 严重性：`high`
- 置信度：`high`
- CWE：CWE-611
- 根因位置：`src/main/java/com/sinkspring/bench/service/CatalogImportService.java:1`

#### 问题与影响

外部输入可能到达 .parse(new InputSource 且缺少禁用外部实体和DOCTYPE

#### 根因

Controller /import 将外部XML请求体传入importCatalog，工厂显式启用外部实体且未禁用DOCTYPE，XXE可利用。

#### 攻击路径

外部输入可能到达 .parse(new InputSource 且缺少禁用外部实体和DOCTYPE

#### 独立复核

漏洞假设得到源码证据支持。调用链完整成立：(1) CatalogController.importCatalog 暴露 POST /api/catalog/import（consumes=APPLICATION_XML_VALUE），将 @RequestBody String content 原样传入 catalogImportService.importCatalog(content)，无任何过滤或清洗；(2) CatalogImportService.importCatalog 构造 DocumentBuilderFactory 后显式执行 setFeature("disallow-doctype-decl", false)、setFeature("external-general-entities", true)、setFeature("external-parameter-entities", true)、setExpandEntityReferences(true)，即不仅未禁用外部实体与 DOCTYPE，反而显式开启，随后 builder.parse(new InputSource(new StringReader(content))) 解析攻击者可控 XML。因此外部输入可到达 .parse(new InputSource) 且外部实体/DOCTYPE 未被禁用，XXE（CWE-611）控制失效成立：可触发外部实体读取/SSRF/实体膨胀 DoS，且 getTextContent() 会将解析结果回显。证据甚至比候选描述更强（不是"缺少禁用"，而是显式启用）。

#### 修复建议

在待由调用者闭包解析的入口到src/main/java/com/sinkspring/bench/service/CatalogImportService.java 中的 .parse(new InputSource之间实施并集中复用禁用外部实体和DOCTYPE。

### 13. unsafe_deserialization：待由调用者闭包解析的入口

- 严重性：`high`
- 置信度：`high`
- CWE：CWE-502
- 根因位置：`src/main/java/com/sinkspring/bench/service/PreferenceService.java:1`

#### 问题与影响

外部输入可能到达 ObjectInputStream 且缺少安全数据格式和类型白名单

#### 根因

证据完整证明从Controller.restore经restoreSnapshot到达ObjectInputStream.readObject，无类型白名单。

#### 攻击路径

外部输入可能到达 ObjectInputStream 且缺少安全数据格式和类型白名单

#### 独立复核

证据支持漏洞假设。Controller 的 POST /api/preferences/restore 通过 @RequestBody 接收 PreferenceRequest（含 String content），直接调用 preferenceService.restoreSnapshot(request.getContent())（file:d53cf9db...:0:1586）。restoreSnapshot 对 content 做 Base64 解码后构造 new ObjectInputStream(new ByteArrayInputStream(payload)) 并调用 readObject()（file:63f6505b...:0:1536），全程未设置 ObjectInputFilter、无类型白名单/校验流、无格式限制。外部可控 HTTP 请求体内容可直接到达 ObjectInputStream.readObject，符合 CWE-502 不安全反序列化。impact=high 依据成立（readObject 无过滤）；likelihood=medium 合理（路径可达性由 controller 证据证明）。

#### 修复建议

在待由调用者闭包解析的入口到src/main/java/com/sinkspring/bench/service/PreferenceService.java 中的 ObjectInputStream之间实施并集中复用安全数据格式和类型白名单。

### 14. unsafe_deserialization：待由调用者闭包解析的入口

- 严重性：`high`
- 置信度：`high`
- CWE：CWE-502
- 根因位置：`src/main/java/com/sinkspring/bench/service/PreferenceService.java:1`

#### 问题与影响

外部输入可能到达 ObjectInputStream 且缺少安全数据格式和类型白名单

#### 根因

restoreSnapshot被Controller.restore调用并直接反序列化攻击者可控字节流，无过滤。

#### 攻击路径

外部输入可能到达 ObjectInputStream 且缺少安全数据格式和类型白名单

#### 独立复核

证据直接证明漏洞假设成立。PreferenceController.restore（POST /api/preferences/restore）以 @RequestBody 接收 PreferenceRequest，其 content 字段为攻击者可控字符串，原样传入 PreferenceService.restoreSnapshot(content)；后者仅做 Base64 解码后直接构造 ObjectInputStream 并调用 readObject()，过程中无类型白名单、ObjectInputFilter、格式校验或任何过滤，且反序列化对象（类名与 toString）被反射回响应。调用链完整：HTTP 入口 → request.getContent() → restoreSnapshot → ObjectInputStream.readObject()。证据中不存在任何安全数据格式或类型白名单控制，符合 CWE-502 不安全反序列化，影响等级 high（潜在 RCE，取决于 classpath gadget），可达性由源码调用链证明。

#### 修复建议

在待由调用者闭包解析的入口到src/main/java/com/sinkspring/bench/service/PreferenceService.java 中的 ObjectInputStream之间实施并集中复用安全数据格式和类型白名单。

### 15. unsafe_deserialization：待由调用者闭包解析的入口

- 严重性：`high`
- 置信度：`high`
- CWE：CWE-502
- 根因位置：`src/main/java/com/sinkspring/bench/service/PreferenceService.java:1`

#### 问题与影响

外部输入可能到达 XMLDecoder 且缺少禁用对象图反序列化

#### 根因

Controller.desktop-import调用importDesktopProfile将content直接交给XMLDecoder.readObject，无对象图禁用。

#### 攻击路径

外部输入可能到达 XMLDecoder 且缺少禁用对象图反序列化

#### 独立复核

源码证据链完整且可复核。PreferenceController 的 @PostMapping("/desktop-import") 端点以 @RequestBody PreferenceRequest 接收外部请求体，直接调用 preferenceService.importDesktopProfile(request.getContent())（证据 d53cf9db...）。PreferenceService.importDesktopProfile 将 content 字符串按 UTF-8 转字节后构造 new XMLDecoder(new ByteArrayInputStream(...)) 并立即调用 decoder.readObject()（证据 63f6505b...），全程无任何类白名单、过滤器、输入校验或替代防护。XMLDecoder 本身不具备"禁用对象图反序列化"的选项，其 readObject 可实例化任意类并调用方法，属于 CWE-502 不安全反序列化。外部输入到达敏感操作、有效控制缺失、输入到敏感操作的路径均由源码直接证明，支持该漏洞假设。

#### 修复建议

在待由调用者闭包解析的入口到src/main/java/com/sinkspring/bench/service/PreferenceService.java 中的 XMLDecoder之间实施并集中复用禁用对象图反序列化。

### 16. unsafe_deserialization：待由调用者闭包解析的入口

- 严重性：`high`
- 置信度：`high`
- CWE：CWE-502
- 根因位置：`src/main/java/com/sinkspring/bench/service/PreferenceService.java:1`

#### 问题与影响

外部输入可能到达 XMLDecoder 且缺少禁用对象图反序列化

#### 根因

importDesktopProfile由HTTP端点驱动，XMLDecoder直接读取攻击者提供XML，无防护。

#### 攻击路径

外部输入可能到达 XMLDecoder 且缺少禁用对象图反序列化

#### 独立复核

证据包内两个文件完整建立了外部输入到 XMLDecoder 的数据路径，漏洞假设成立。PreferenceController 的 @PostMapping("/desktop-import") 以 @RequestBody PreferenceRequest 接收外部请求体，将 request.getContent() 直接传入 PreferenceService.importDesktopProfile(content)；该方法对 content.getBytes(StandardCharsets.UTF_8) 直接构造 XMLDecoder 并调用 readObject()，路径上无任何输入校验、白名单或反序列化限制。XMLDecoder.readObject() 解析攻击者可控 XML 时可实例化任意 Java 对象图（CWE-502），且 importDesktopProfile 在字节层面不区分内容类型、无任何禁用对象图反序列化的机制。候选所称的"入口待调用者闭包解析"实际已由 controller 证据解析为 HTTP 端点，调用者、数据流与 sink 均在证据包中直接可见。

#### 修复建议

在待由调用者闭包解析的入口到src/main/java/com/sinkspring/bench/service/PreferenceService.java 中的 XMLDecoder之间实施并集中复用禁用对象图反序列化。

### 17. unsafe_deserialization：POST /api/preferences/restore（JSON body 含 content）

- 严重性：`high`
- 置信度：`high`
- CWE：CWE-502
- 根因位置：`src/main/java/com/sinkspring/bench/service/PreferenceService.java:1`

#### 问题与影响

若 restoreSnapshot 直接反序列化攻击者可控字节流，可通过 gadget 链达成远程代码执行。

#### 根因

POST/restore经Controller将content传给restoreSnapshot，Base64解码后ObjectInputStream.readObject直接执行，链完整且无白名单。

#### 攻击路径

若 restoreSnapshot 直接反序列化攻击者可控字节流，可通过 gadget 链达成远程代码执行。

#### 独立复核

漏洞假设（restoreSnapshot 反序列化攻击者可控字节流导致不安全反序列化/CWE-502）得到源码证据支持。链路完整：PreferenceController.restore 通过 @RequestBody PreferenceRequest 接收攻击者可控 content（d53c...:17-22），调用 preferenceService.restoreSnapshot(request.getContent())（d53c...:20）；PreferenceService.restoreSnapshot 对 content 做 Base64 解码后直接构造 ObjectInputStream 并调用 readObject()（63f6...:19-22），该方法无 ObjectInputFilter、无类型白名单/黑名单过滤，返回值随后被用于 snapshot.getClass()/toString()，说明反序列化确实执行。攻击者可控输入到达 readObject 这一敏感操作，控制失效成立。RCE 影响判定基于 Java 原生反序列化 gadget 链的既有前提，属该漏洞类别标准影响，代码层面已足以确认漏洞假设成立。

#### 修复建议

在POST /api/preferences/restore（JSON body 含 content）到对象实例化（可触发 gadget 链实现 RCE）之间实施并集中复用方法声明抛出 ClassNotFoundException，强烈指向 ObjectInputStream.readObject 且无可见类型过滤。

### 18. xss：GET /api/pages/search?query=<payload>

- 严重性：`medium`
- 置信度：`high`
- CWE：CWE-79
- 根因位置：`src/main/java/com/sinkspring/bench/controller/PageController.java:1`

#### 问题与影响

若 buildSearchPage 未对 query 做 HTML 转义，攻击者可控输入将原样进入 HTML 响应导致反射型 XSS。

#### 根因

PageService.buildSearchPage直接拼接query到HTML字符串，无任何转义，且控制器以text/html返回，形成反射型XSS。

#### 攻击路径

若 buildSearchPage 未对 query 做 HTML 转义，攻击者可控输入将原样进入 HTML 响应导致反射型 XSS。

#### 独立复核

源码证明控制失效成立：PageController.search 通过 @RequestParam String query 直接接收攻击者可控输入，端点 produces=MediaType.TEXT_HTML_VALUE，将 buildSearchPage(query) 结果作为 text/html 响应体返回；PageService.buildSearchPage 将 query 未经任何 HTML 转义直接字符串拼接进 "<html><body>...Results for " + query + "..." 响应，攻击者提交的 <script> 等载荷将原样进入浏览器渲染的 HTML 响应，构成反射型 XSS。对照证据 buildSearchText 使用 HtmlUtils.htmlEscape(query)，说明同一服务具备转义手段但未应用于 buildSearchPage 路径，进一步支持漏洞假设。可达路径（GET /api/pages/search?query=<payload> 到 text/html 响应体）由所给源码完整证明。

#### 修复建议

在GET /api/pages/search?query=<payload>到浏览器渲染的 text/html 响应之间实施并集中复用produces=MediaType.TEXT_HTML_VALUE 明确按 HTML 输出，控制器层无任何过滤或转义。

### 19. hardcoded_secret：POST /api/session/login

- 严重性：`medium`
- 置信度：`high`
- CWE：CWE-798
- 根因位置：`src/main/java/com/sinkspring/bench/service/SessionService.java:1`

#### 问题与影响

若openSession以硬编码或弱密钥签名且未绑定算法，攻击者可伪造任意accountId/role的token

#### 根因

SessionService硬编码了签名密钥SIGNING_KEY与操作员凭据，且readSession仅解码不验签，攻击者可凭硬编码密钥伪造ADMIN角色token访问export。

#### 攻击路径

若openSession以硬编码或弱密钥签名且未绑定算法，攻击者可伪造任意accountId/role的token

#### 独立复核

源码证实了核心控制失效：SessionService.readSession仅调用JWT.decode（auth0 java-jwt的decode不验签），AccountController的GET /api/accounts/admin/export直接将该未验证token的role claim传给accountService.exportAccounts，因此攻击者可自造任意role=ADMIN的token（无需任何密钥）触发导出；同时SIGNING_KEY="sinkspring-session-key"为硬编码常量属实（CWE-798）。但题述机制不准确：算法已绑定——openSession与verifySession均显式使用Algorithm.HMAC256(SIGNING_KEY)，不存在"未绑定算法"；伪造能力来自出口端点缺失验签而非密钥强弱；"任意accountId"未被证实——所提供的AccountController以X-Account-Id请求头做账户授权，未消费JWT subject，且SessionController.details走verifySession需密钥；login端点返回固定claims（subject=ACC-9001, role=ADMIN）的token，经login本身无法获得"任意"claims。核心漏洞假设（可伪造token并造成未授权访问）由源码支持，但候选的机制描述、路径与影响表述需修正。

#### 修复建议

在POST /api/session/login到向客户端返回token之间实施并集中复用预取代码未暴露凭据校验细节与密钥来源。

### 20. unsafe_deserialization：POST /api/preferences/desktop-import（JSON body 含 content）

- 严重性：`high`
- 置信度：`high`
- CWE：CWE-502
- 根因位置：`src/main/java/com/sinkspring/bench/service/PreferenceService.java:1`

#### 问题与影响

若 desktop 导入直接解析二进制序列化数据且缺乏校验，同样存在不安全反序列化风险。

#### 根因

PreferenceService.importDesktopProfile直接使用XMLDecoder.readObject()解析攻击者可控content，构成不安全XML反序列化，可导致RCE。

#### 攻击路径

若 desktop 导入直接解析二进制序列化数据且缺乏校验，同样存在不安全反序列化风险。

#### 独立复核

源码证据支持该漏洞假设。PreferenceController.importDesktop 将 @RequestBody PreferenceRequest.content 直接传入 preferenceService.importDesktopProfile(content)；PreferenceService.importDesktopProfile 以 UTF-8 将 content 转为 ByteArrayInputStream 并调用 XMLDecoder.readObject() 返回 Object，证据内未发现任何格式校验、类白名单或过滤。XMLDecoder 可基于 XML 实例化任意类并调用任意方法，属公认不安全反序列化入口（CWE-502），攻击者可控 content 具备 RCE 潜力；控制器随后调用 profile.getClass().getName()/toString() 并返回响应，不构成缓解。desktop-import 端点的不安全反序列化漏洞假设成立。

#### 修复建议

在POST /api/preferences/desktop-import（JSON body 含 content）到Object profile 对象实例化之间实施并集中复用返回 Object 类型且无异常声明，导入格式解析方式不可见。

### 21. sql_injection：GET /api/orders/legacy/view?orderId=<payload>

- 严重性：`high`
- 置信度：`high`
- CWE：CWE-89
- 根因位置：`src/main/java/com/sinkspring/bench/controller/OrderController.java:1`

#### 问题与影响

若 handleLegacyRequest 采用字符串拼接构造查询，orderId 可注入 SQL 语句。

#### 根因

orderId经legacy/view→handleLegacyRequest→findOrderById直接拼接进SQL并由Statement执行，无参数化或过滤。

#### 攻击路径

若 handleLegacyRequest 采用字符串拼接构造查询，orderId 可注入 SQL 语句。

#### 独立复核

漏洞假设被源码证明。完整链路：GET /api/orders/legacy/view 的 @RequestParam orderId（攻击者可控）→ OrderController.legacyViewOrder 将 orderId 原样放入 OrderRequestDTO → OrderService.handleLegacyRequest 将 orderId 放入 OrderContext（queryType=LEGACY）→ LegacyOrderDAO.findOrderById 中 `"SELECT * FROM orders WHERE order_id = '" + orderId + "'"` 字符串拼接，再经 `Statement.executeQuery(sql)` 执行。证据显示全链路无参数化、无 PreparedStatement、无输入过滤或转义，攻击者注入的 SQL 直接进入数据库查询执行（影响面含 UNION/布尔盲注等单语句注入；堆叠查询取决于驱动/DB配置）。问题中的“handleLegacyRequest 采用字符串拼接”实际由其调用的 findOrderById 完成，调用链与拼接点均由所给源码直接证明。

#### 修复建议

在GET /api/orders/legacy/view?orderId=<payload>到数据库查询执行之间实施并集中复用legacy 命名提示旧代码路径，orderId 未经任何过滤进入服务层。

### 22. sql_injection：POST /api/products/list

- 严重性：`high`
- 置信度：`high`
- CWE：CWE-89
- 根因位置：`src/main/java/com/sinkspring/bench/controller/ProductController.java:1`

#### 问题与影响

JSON体字段全量可控，注入面比GET入口更完整，需确认WHERE与ORDER BY是否拼接

#### 根因

list入口的DTO全字段经构造器复制后，sortBy/sortOrder进入${}拼接，validateSortField不拒绝任何输入。

#### 攻击路径

JSON体字段全量可控，注入面比GET入口更完整，需确认WHERE与ORDER BY是否拼接

#### 独立复核

漏洞假设成立。源码证据完整证明数据流与拼接点：POST /api/products/list 将请求体 ProductQueryDTO 全字段（含 sortBy/sortOrder 字符串）直接绑定（ProductController.listProducts）；ProductService.listProducts 经 ProductSearchCriteria 构造器复制全部字段，enrichCriteria 仅补默认值，validateSortField 对含 "--"、";" 的输入仅打日志、不拒绝、不白名单（ProductValidator）；ProductMapper.xml 的 listProducts 中 ORDER BY ${sortField} ${sortDirection} 使用 MyBatis ${} 字符串拼接，且无任何过滤/白名单，构成 ORDER BY SQL 注入（CWE-89）。WHERE 子句 category = #{category} 与 LIMIT #{pageSize} 为参数绑定，不拼接。攻击面：未认证的 POST 请求即可控制 ORDER BY 片段，无需管理员权限。

#### 修复建议

在POST /api/products/list到SQL查询执行之间实施并集中复用预取代码对该入口无任何校验、白名单或过滤。

### 23. sql_injection：GET /api/products/featured?sort=

- 严重性：`high`
- 置信度：`high`
- CWE：CWE-89
- 根因位置：`src/main/java/com/sinkspring/bench/controller/ProductController.java:1`

#### 问题与影响

sort未经白名单校验进入ORDER BY时构成注入，可控面窄于前两个入口

#### 根因

featured入口的sort参数进入sortField并到达${}拼接，sortDirection固定ASC但sort仍完全可控且Validator不拦截。

#### 攻击路径

sort未经白名单校验进入ORDER BY时构成注入，可控面窄于前两个入口

#### 独立复核

漏洞假设被证据支持。数据流完整可核：GET /api/products/featured 中 @RequestParam sort 直接赋给 ProductQueryDTO.sortBy（controller 证据），经 ProductSearchCriteria 构造器映射为 sortField（ProductSearchCriteria 证据），ProductService.getFeaturedProducts 调用 productValidator.validateAndSanitize(criteria) 后执行 productMapper.getFeaturedProducts(criteria)（service 证据）。validateAndSanitize 仅在 sortField 含单引号时打日志，不做任何拦截或清洗；ALLOWED_FIELDS 白名单虽已定义但从未在 featured 路径（validateAndSanitize）生效（validator 证据）。Mapper 中 getFeaturedProducts 以 ORDER BY ${sortField} ${sortDirection} 直接拼接执行（mapper XML 证据）。sortDirection 在 featured 入口未设置、由 ProductSearchCriteria 默认 ASC，但 sortField 完全由攻击者控制且无有效白名单校验，构成 ORDER BY 注入，影响 SQL 查询执行。可控面窄于前两个入口的陈述与代码一致（仅 sort 可控，sortDirection 固定）。

#### 修复建议

在GET /api/products/featured?sort=到SQL查询执行之间实施并集中复用category固定为FEATURED、limit固定为10，但sort完全用户可控且无白名单。

### 24. jwt_verification_bypass：待由调用者闭包解析的入口

- 严重性：`high`
- 置信度：`high`
- CWE：CWE-347
- 根因位置：`src/main/java/com/sinkspring/bench/service/SessionService.java:1`

#### 问题与影响

外部输入可能到达 JWT.decode 且缺少验签后再信任声明

#### 根因

AccountController.export以Authorization头直接调用readSession，JWT.decode仅解码不验签，解码后role直接进入exportAccounts的ADMIN判定，满足外部输入到sink且控制失效。

#### 攻击路径

外部输入可能到达 JWT.decode 且缺少验签后再信任声明

#### 独立复核

证据支持漏洞假设。调用链完整且可由给定源码独立证明：(1) 入口为 AccountController.export（@RestController @GetMapping("/api/accounts/admin/export")），Authorization 请求头作为外部输入传入 sessionService.readSession（file:b47b09...AccountController.java 第45-47行）；(2) SessionService.readSession 调用 JWT.decode(token)，仅解码不验签（file:31d77e...SessionService.java 第27-32行），而同一文件中 verifySession 使用 JWT.require(HMAC256).verify 作为对照，证明开发者明确区分解码与验签，readSession 路径确实无验签；(3) 解码后的 role 声明直接传入 accountService.exportAccounts，该方法仅校验字符串等于"ADMIN"即返回 accountRepository.findAll()（file:ca32f4...AccountService.java），故攻击者可自造任意签名/任意 payload 的 JWT（role=ADMIN）绕过授权检查读取全部账户数据，构成 CWE-347 JWT 验签绕过，外部输入到达敏感操作且控制失效，影响为未授权数据泄露。

#### 修复建议

在待由调用者闭包解析的入口到src/main/java/com/sinkspring/bench/service/SessionService.java 中的 JWT.decode之间实施并集中复用验签后再信任声明。

### 25. sql_injection：经未知HTTP控制器传入的OrderContext

- 严重性：`high`
- 置信度：`high`
- CWE：CWE-89
- 根因位置：`src/main/java/com/sinkspring/bench/controller/OrderController.java:1`

#### 问题与影响

orderId未过滤拼入单引号SQL,可布尔/联合/报错注入读取orders全表并回显结果或DB错误细节

#### 根因

证据链完整：OrderController.getOrderById将@PathVariable orderId写入OrderRequestDTO，经OrderService构建OrderContext，LegacyOrderDAO.findOrderById直接拼接进SQL并由Statement.executeQuery执行，异常消息回显

#### 攻击路径

orderId未过滤拼入单引号SQL,可布尔/联合/报错注入读取orders全表并回显结果或DB错误细节

#### 独立复核

证据支持该SQL注入假设。OrderController.getOrderById(@PathVariable orderId)、/legacy/view(@RequestParam orderId)及/process(@RequestBody)三个HTTP入口将用户可控orderId经OrderRequestDTO→OrderContextFactory→OrderService传入LegacyOrderDAO.findOrderById/executeOrderQuery，其中直接拼接 `SELECT * FROM orders WHERE order_id = '" + orderId + "'`，无过滤、无参数化，由Statement.executeQuery执行；catch块将e.getMessage()写入response.message返回调用方，resultSet的order_id/status也写入OrderResponseVO返回。攻击者可控输入直达敏感操作且结果/错误均回显，布尔、联合、报错注入均可行，未发现任何有效防护。

#### 修复建议

在经未知HTTP控制器传入的OrderContext到Statement.executeQuery(sql)之间实施并集中复用无PreparedStatement参数化、无输入校验,异常文本回显调用方。

### 26. security_misconfiguration：WebConfig.addCorsMappings（Spring启动时自动装配全局CORS）

- 严重性：`medium`
- 置信度：`high`
- CWE：CWE-16
- 根因位置：`src/main/java/com/sinkspring/bench/config/WebConfig.java:1`

#### 问题与影响

通配CORS使任何网页都能发起并读取本应用全部端点响应，若端点返回敏感数据或依赖非Cookie凭据则可能被跨域窃取

#### 根因

全局CORS允许任意源、任意方法/头，且无allowCredentials，浏览器可直接跨域读取受控端点响应；现有控制器无安全过滤器，多个无认证端点（文档、订单、集成预览）返回敏感数据，CORS松弛导致跨域窃取成立。

#### 攻击路径

通配CORS使任何网页都能发起并读取本应用全部端点响应，若端点返回敏感数据或依赖非Cookie凭据则可能被跨域窃取

#### 独立复核

源码证据支持该漏洞假设。WebConfig.addCorsMappings 对 "/**" 注册 allowedOrigins("*")、allowedMethods("*")、allowedHeaders("*")（root_control 文件），证明全局通配CORS已装配且覆盖全部路径。AccountController（/api/accounts/me、/{accountId}、/admin/export）返回账户记录，DocumentController（/content、/published）返回文档内容，IntegrationController（/preview、/catalogs/{catalog}）返回集成内容，均属可被跨域读取的响应；其认证依赖 X-Account-Id / Authorization 请求头（非Cookie凭据），且文档与集成端点无任何认证校验，allowedHeaders("*") 使携带自定义头的跨域预检得以通过。问题中的条件句（端点返回敏感数据或依赖非Cookie凭据）被源码满足，通配CORS使任意网页可发起并读取响应。未调用 allowCredentials(true) 仅排除Cookie自动携带，对本应用基于请求头的认证场景不构成防护，反而暴露无认证端点。

#### 修复建议

在WebConfig.addCorsMappings（Spring启动时自动装配全局CORS）到任意站点可跨域读取本应用HTTP响应之间实施并集中复用未调用allowCredentials(true)，浏览器阻止携带Cookie的CORS请求。

### 27. unknown：登录接口（LoginRequest DTO来源，控制器与路由未在证据中）

- 严重性：`medium`
- 置信度：`high`
- CWE：未分类
- 根因位置：`src/main/java/com/sinkspring/bench/dto/LoginRequest.java:1`

#### 问题与影响

password信号表明存在登录认证逻辑，其口令比较方式、失败处理与枚举防护均未证实

#### 根因

证据显示登录接口POST /api/session/login绑定LoginRequest并调用SessionService，仅用源码内硬编码明文口令equals比较，成功后签发HMAC256 JWT，登录认证控制可利用失效。

#### 攻击路径

password信号表明存在登录认证逻辑，其口令比较方式、失败处理与枚举防护均未证实

#### 独立复核

证据支持硬编码凭据导致的认证控制失效漏洞。SessionController（@RestController + @RequestMapping("/api/session") + @PostMapping("/login") + @RequestBody 绑定 LoginRequest）证明登录路由可达且输入可到达 SessionService.openSession；SessionService 源码显示认证仅用源码内硬编码常量 OPERATOR_USERNAME="ops-admin"、OPERATOR_PASSWORD="SpringOps#2026" 经 String.equals 明文比较，失败抛 IllegalArgumentException，成功后以硬编码密钥 "sinkspring-session-key" 签发 HMAC256 JWT（subject=ACC-9001、role=ADMIN、8小时有效）。因此攻击者掌握源码或可反编译应用即直接获得有效凭据，且硬编码 JWT 签名密钥可被用于伪造管理员令牌（CWE-798 硬编码凭据/密钥），认证控制失效构成所调查的安全问题。

#### 修复建议

在登录接口（LoginRequest DTO来源，控制器与路由未在证据中）到认证结果与会话/令牌签发（实现未见）之间实施并集中复用未知，需补读认证实现才能判定防护。

### 28. hardcoded_secret：document-hub 合作伙伴集成（配置级）

- 严重性：`medium`
- 置信度：`high`
- CWE：CWE-798
- 根因位置：`src/main/resources/application.yml:1`

#### 问题与影响

密钥泄露即导致攻击者冒用生产合作伙伴身份调用document-hub API

#### 根因

ResourceSyncService通过@Value注入partners.document-hub.client-secret，并在loadCatalog出站请求中以X-Client-Secret头发送，明文密钥到出站Sink链路完整，未见加密或密钥管理控制。

#### 攻击路径

密钥泄露即导致攻击者冒用生产合作伙伴身份调用document-hub API

#### 独立复核

源码证据支持该漏洞假设。application.yml 以明文硬编码生产级合作伙伴凭据（client-id: sinkspring-production；client-secret: dh_live_Q7m4pN8xK2vL6sR9），无环境变量引用、无加密或外部密钥管理；ResourceSyncService 通过 @Value 注入 clientSecret 并在 loadCatalog() 出站 HTTPS 请求中以 X-Client-Secret 请求头发送，X-Client-Id/X-Client-Secret 是出站鉴权的唯一凭据，未见签名、轮换或附加校验。因此持有该明文值即可凭同一静态共享凭据冒充生产合作伙伴调用该出站 API——密钥泄露即冒用身份的假设成立（CWE-798 硬编码凭据）。

#### 修复建议

在document-hub 合作伙伴集成（配置级）到document-hub 出站HTTPS请求的鉴权凭据之间实施并集中复用无加密或外部注入可见，live级密钥明文入库。

### 29. sql_injection：首页精选产品接口（控制器名待补证）

- 严重性：`high`
- 置信度：`high`
- CWE：CWE-89
- 根因位置：`src/main/java/com/sinkspring/bench/controller/ProductController.java:1`

#### 问题与影响

硬编码 LIMIT 不影响 ORDER BY 注入，仍可进行盲注或报错注入

#### 根因

GET /api/products/featured 的 sort 参数经控制器、服务直达 ProductMapper.getFeaturedProducts，XML 中 ORDER BY ${sortField} 直接插值，validateAndSanitize 无白名单仅日志，构成可利用SQL注入

#### 攻击路径

硬编码 LIMIT 不影响 ORDER BY 注入，仍可进行盲注或报错注入

#### 独立复核

漏洞假设成立（supported）。证据链完整可复核：(1) 入口已证实——ProductController.getFeaturedProducts 映射 GET /api/products/featured，其 `sort` 请求参数（默认 created_at）写入 DTO.sortBy（候选所称"控制器名待补证"实已被该证据证实）；(2) 服务层 ProductService.getFeaturedProducts 构造 ProductSearchCriteria 后调用 productValidator.validateAndSanitize(criteria)，再调用 productMapper.getFeaturedProducts(criteria)；(3) ProductValidator.validateAndSanitize 仅对 null 赋值默认值、对含 `'` 的输入打日志，不进行白名单或字符过滤，ALLOWED_FIELDS 未在本路径被引用，`isValidSortField` 也只判非空，无实际防护；(4) ProductMapper.xml 中 getFeaturedProducts 的 `ORDER BY ${sortField} ${sortDirection}` 为 MyBatis ${} 原生插值，紧随其后的 `LIMIT 10` 在 SQL 语义上位于 ORDER BY 求值之后，不阻止 ORDER BY 内注入表达式求值，盲注（条件排序/时间延迟）与报错注入（如 ORDER BY 内使用报错函数）仍可行。故"硬编码 LIMIT 不影响 ORDER BY 注入"的核心主张由源码证明，rootCause、数据流、可达性与影响（CWE-89，high）均得到支持。

#### 修复建议

在首页精选产品接口（控制器名待补证）到getFeaturedProducts 的 ORDER BY ${sortField} ${sortDirection}之间实施并集中复用LIMIT 10 为硬编码不构成防护，排序参数 ${} 插值且白名单未证实。

### 30. ssrf：POST /api/integrations/updates

- 严重性：`medium`
- 置信度：`high`
- CWE：CWE-918
- 根因位置：`src/main/java/com/sinkspring/bench/controller/IntegrationController.java:1`

#### 问题与影响

请求体携带的目标地址未经校验即用于出站请求，攻击者可指向内网服务形成SSRF。

#### 根因

RemoteRequest.callback经/updates入口直达deliverUpdate，并作为URL打开HttpURLConnection发送POST，无协议或主机限制。

#### 攻击路径

请求体携带的目标地址未经校验即用于出站请求，攻击者可指向内网服务形成SSRF。

#### 独立复核

证据链完整支持SSRF漏洞假设。(1) 入口：IntegrationController.sendUpdate以@RequestBody RemoteRequest接收POST /api/integrations/updates，将请求体直接传给resourceSyncService.deliverUpdate(request)；(2) 传播：ResourceSyncService.deliverUpdate对request.getCallback()执行URI.create(...).toURL()并openConnection()发送POST，payload亦由请求体提供；(3) 无校验：在已提供的源码中，callback在从请求体到出站连接之间未经过任何协议、主机或内网地址白名单校验，DTO为纯数据载体。攻击者可提交http/https内网地址（如http://127.0.0.1:<port>/）触发服务端出站请求，符合CWE-918 SSRF。控制失效（未经校验的输入到达出站敏感操作）已由源码直接证明。

#### 修复建议

在POST /api/integrations/updates到出站HTTP客户端连接远程地址之间实施并集中复用未观察到目标地址协议或主机白名单。

### 31. sensitive_data_exposure：返回SystemTaskResponse对象的接口（入口待证实）

- 严重性：`medium`
- 置信度：`high`
- CWE：未分类
- 根因位置：`src/main/java/com/sinkspring/bench/controller/SystemController.java:1`

#### 问题与影响

若该接口对外可达，则泄露系统命令输出与内部实现信息。

#### 根因

SystemController公开返回SystemTaskResponse，命令输出与异常消息直接序列化回客户端

#### 攻击路径

若该接口对外可达，则泄露系统命令输出与内部实现信息。

#### 独立复核

源码证据支持该条件性漏洞假设。SystemController（@RestController，@RequestMapping("/api/system")）的四个端点（POST /backup、GET /backup/quick、POST /restore、GET /diagnostics）均直接返回 SystemTaskResponse 对象；BackupService 将用户可控参数拼入 shell 命令并调用 NativeProcessHandler.executeShellCommand；NativeProcessHandler 将子进程 stdout/stderr 拼接进 output（stderr 带"[ERROR]"前缀）、设置 exitCode，并在异常时将 e.getMessage() 写入 message；SystemTaskResponse 含 success/message/output/exitCode 字段（@Data），无任何脱敏或过滤。因此，若任一该端点对外可达，HTTP 响应体将泄露命令执行输出、退出码及内部异常消息，条件性信息泄露主张成立。注意：证据仅证明"泄露路径"存在，不证明端点实际对外可达或无认证。

#### 修复建议

在返回SystemTaskResponse对象的接口（入口待证实）到HTTP响应暴露命令执行输出、退出码与内部异常消息之间实施并集中复用无任何脱敏、裁剪或访问控制。

### 32. hardcoded_secret：Spring启动加载src/main/resources/application.yml

- 严重性：`medium`
- 置信度：`high`
- CWE：CWE-798
- 根因位置：`src/main/resources/application.yml:1`

#### 问题与影响

若配置含明文口令或密钥则构成硬编码秘密泄露。

#### 根因

application.yml存在明文数据源口令和client-secret，构成硬编码秘密。

#### 攻击路径

若配置含明文口令或密钥则构成硬编码秘密泄露。

#### 独立复核

证据直接证实了问题中的条件假设。所给证据为已批准的配置路径 src/main/resources/application.yml（Spring Boot 标准资源位置），其正文包含：spring.datasource.password 明文值 "app_admin_2026"，以及 partners.document-hub.client-secret 明文值 "dh_live_Q7m4pN8xK2vL6sR9"（"dh_live" 前缀暗示生产用途）。配置中未见 ${...} 占位符或环境变量引用替代这些值。配置属于仓库内随应用打包的落盘文件，明文口令/密钥可被读取，满足"配置含明文口令或密钥则构成硬编码秘密泄露"（CWE-798）的前提，漏洞假设成立。

#### 修复建议

在Spring启动加载src/main/resources/application.yml到数据源口令、密钥等敏感信息明文落盘并可被读取之间实施并集中复用未知，需读取批准的配置正文核实。

### 33. hardcoded_secret：登录接口调用 SessionService.openSession

- 严重性：`medium`
- 置信度：`high`
- CWE：CWE-798
- 根因位置：`src/main/java/com/sinkspring/bench/service/SessionService.java:1`

#### 问题与影响

硬编码凭据与签名密钥固化于源码，攻击者获知后可直接伪造管理员令牌且口令无法轮换

#### 根因

SessionService以常量固化口令SpringOps#2026和HMAC密钥sinkspring-session-key，可直接伪造管理员令牌。

#### 攻击路径

硬编码凭据与签名密钥固化于源码，攻击者获知后可直接伪造管理员令牌且口令无法轮换

#### 独立复核

源码证据支持该漏洞假设。SessionService.java 中 OPERATOR_PASSWORD("SpringOps#2026") 与 SIGNING_KEY("sinkspring-session-key") 均为编译期常量：openSession 直接以常量比对口令，并以 Algorithm.HMAC256(SIGNING_KEY) 签发 subject=ACC-9001、role=ADMIN 的 8 小时令牌；verifySession 用同一硬编码密钥验签。任何获知该密钥者可离线伪造被 verifySession 接受的 ADMIN 令牌，口令/密钥轮换须改码重部署。影响路径亦获证据支撑：AccountController./api/accounts/admin/export 调用 readSession（仅 JWT.decode 不验签）后直接以 token 的 role 声明作为管理员导出门禁；SessionController./api/session/login 为 openSession 的调用入口。未发现可抵消该控制失效的防护。

#### 修复建议

在登录接口调用 SessionService.openSession到JWT.sign(Algorithm.HMAC256(SIGNING_KEY)) 与常量口令比对之间实施并集中复用无外部配置覆盖迹象，application.yml 是否覆盖密钥待查。

### 34. hardcoded_secret：application.yml配置加载

- 严重性：`medium`
- 置信度：`high`
- CWE：CWE-798
- 根因位置：`src/main/resources/application.yml:1`

#### 问题与影响

数据源口令硬编码入库，配置泄露即可导致数据库被接管。

#### 根因

spring.datasource.password明文app_admin_2026写入application.yml，DataSource初始化直接使用。

#### 攻击路径

数据源口令硬编码入库，配置泄露即可导致数据库被接管。

#### 独立复核

漏洞假设的核心主张由证据直接证明：src/main/resources/application.yml（位于仓库快照 sinkspring-bench-eval-v1 内）以明文写入 spring.datasource.username=app_admin 与 password=app_admin_2026，即数据源口令已硬编码入库（CWE-798）。该配置为标准 Spring Boot DataSource 属性结构，DataSource 自动配置会直接消费该口令连接 jdbc:h2:mem:sinkspring_db；所给分片内容中不存在 ${...} 环境变量占位符或加密处理器覆盖声明。同时 spring.h2.console.enabled=true 表明口令泄露后存在经 H2 控制台操作内存库的合理路径。核心"口令明文入库"事实与"配置泄露"前提下的影响表述一致，severity=medium 的评级未夸大。

#### 修复建议

在application.yml配置加载到jdbc:h2:mem:sinkspring_db数据库连接凭证之间实施并集中复用未见环境变量占位符或加密处理器覆盖该口令。

## 待独立复核候选

### sql_injection：GET /api/products/search

sortBy/sortOrder直接拼入ORDER BY且keyword/category拼入WHERE时将构成注入，需服务层证明拼接方式

- 调查编号：`investigation-22`
- 建议严重性：`high`

### jwt_verification_bypass：GET /api/session/details

若verifySession跳过签名校验、存在算法混淆或密钥可猜测，攻击者可伪造token读取任意账户的accountId与role

- 调查编号：`investigation-26`
- 建议严重性：`high`

### sensitive_data_exposure：GET /api/system/diagnostics?targetPath=

targetPath指向任意文件/目录时诊断结果可能回显文件内容或路径元数据造成敏感数据暴露

- 调查编号：`investigation-34`
- 建议严重性：`medium`

### sensitive_data_exposure：任意端点抛出未处理异常时触发的 /sinkspring/error

攻击者触发异常即可获得内部实现细节并辅助后续注入或绕过

- 调查编号：`investigation-35`
- 建议严重性：`medium`

## 未决问题

- 最终发现仅包含独立复核支持的候选；覆盖限制见确定性报告。

## 覆盖与限制

完整安全审计：`false`

- 仍有入口、敏感操作或配置发现包未成功处理
- 仍有未收口的调查、基线问题或候选复核
- 仍有未完成安全审阅声明的文件
- 独立基线尚未提交调查问题
- 尚未建立结构化威胁模型

静态分析结果均需复核；导出不表示完整覆盖或动态复现。可能包含敏感源码，请勿公开上传。
