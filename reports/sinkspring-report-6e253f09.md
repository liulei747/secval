# Secval 安全审计报告

- 任务 ID：`6e253f09ae7d40e2b599c8a492b4ed4c`
- 状态：`needs_review`
- 报告收口：`partial_report`

## 执行摘要

本次审计经独立静态复核确认 36 条正式安全发现，最高严重性为 high。arbitrary_file_write：待由调用者闭包解析的入口；object_level_authorization：getOrderById；object_level_authorization：GET /api/accounts/me；jndi_injection：待由调用者闭包解析的入口；ssrf：待由调用者闭包解析的入口；另有 31 条。每条发现均在下文列出根因位置、攻击路径、复核结论和修复建议；未覆盖范围与静态分析限制见“覆盖与限制”。

## 安全发现

### 1. arbitrary_file_write：待由调用者闭包解析的入口

- 严重性：`high`
- 置信度：`high`
- CWE：CWE-73
- 根因位置：`src/main/java/com/sinkspring/bench/service/DocumentService.java:1`

#### 问题与影响

外部输入可能到达 Files.writeString 且缺少规范化后目录边界检查

#### 根因

storeDocument接收DocumentRequest.path，经documentRoot.resolve后直接Files.writeString，无规范化也无目录边界检查，路径穿越漏洞成立。

#### 攻击路径

外部输入可能到达 Files.writeString 且缺少规范化后目录边界检查

#### 独立复核

漏洞假设被源码证明。数据流完整可核：(1) 外部输入源——DocumentController.putContent 以 @RequestBody DocumentRequest 接收 HTTP POST /api/documents/content 的 path 字段（DTO 为 Lombok @Data，path 无校验注解）；(2) 传递——直接调用 documentService.storeDocument(request)；(3) 汇点——storeDocument 中 documentRoot.resolve(request.getPath()) 后未经 normalize()、无 startsWith/toRealPath 等目录边界检查，直接 Files.writeString(document, content, UTF_8, CREATE, TRUNCATE_EXISTING)，且 parent 目录不存在时自动 createDirectories。攻击者可用绝对路径（resolve 遇绝对路径直接采用）或 ../ 相对路径逃逸 documentRoot（如 java.io.tmpdir/sinkspring-documents 之外），实现任意文件写入/覆盖（CWE-73）。loadPublishedDocument 中的 toRealPath+startsWith 防护仅存在于读取路径，不覆盖写入路径，反证了作者知晓该风险但未在 storeDocument 中实施。可达性由控制器映射直接闭环，无需调用者闭包解析。

#### 修复建议

在待由调用者闭包解析的入口到src/main/java/com/sinkspring/bench/service/DocumentService.java 中的 Files.writeString之间实施并集中复用规范化后目录边界检查。

### 2. object_level_authorization：getOrderById

- 严重性：`medium`
- 置信度：`high`
- CWE：CWE-639
- 根因位置：`src/main/java/com/sinkspring/bench/controller/OrderController.java:1`

#### 问题与影响

请求资源ID可能在没有对象级授权时访问其他主体的数据

#### 根因

getOrderById仅凭路径orderId调用getOrderDetails并返回，控制器层无归属或对象级授权校验。

#### 攻击路径

请求资源ID可能在没有对象级授权时访问其他主体的数据

#### 独立复核

证据支持该IDOR/BOLA漏洞假设。完整调用链在证据包内可见且不含任何对象级授权：OrderController.getOrderById接收@PathVariable orderId（OrderController.java:26-35），经OrderRequestDTO传入OrderService.getOrderDetails；OrderService.buildContext（OrderContextFactory.buildContext）仅复制orderId/customerId并固定queryType="SELECT"，随后直接调用LegacyOrderDAO.findOrderById，无任何归属或所有权校验（OrderService.java:25-31, OrderContextFactory.java:8-22）。DAO将orderId直接拼接为"SELECT * FROM orders WHERE order_id = '<orderId>'"（LegacyOrderDAO.java:22-27），结果返回order_id与status，全程无owner/customer过滤条件。OrderContext/OrderRequestDTO虽含customerId字段（OrderContext.java:8-13, OrderRequestDTO.java:8-12），但查询构造从未使用它，证明预期的归属维度未被实施为控制。从HTTP入口到SQL敏感操作的整个数据流均以攻击者可控orderId为唯一键，且在包内未发现任何反向证据（如安全过滤器、拦截器或归属校验）推翻此结论。候选所列"OrderService内部未展示"的限制已被证据包实际包含的OrderService.java否定，该服务同样无授权逻辑。

#### 修复建议

在getOrderById到按请求资源ID读取或修改对象之间实施并集中复用对象归属或租户范围校验。

### 3. object_level_authorization：GET /api/accounts/me

- 严重性：`medium`
- 置信度：`high`
- CWE：CWE-639
- 根因位置：`src/main/java/com/sinkspring/bench/controller/AccountController.java:1`

#### 问题与影响

若getCurrentAccount未校验该ID对应的有效会话或账户归属，攻击者可伪造任意X-Account-Id读取他人账户数据（IDOR）。

#### 根因

X-Account-Id直接作为requesterId传入getCurrentAccount并返回结果，无认证或归属校验。

#### 攻击路径

若getCurrentAccount未校验该ID对应的有效会话或账户归属，攻击者可伪造任意X-Account-Id读取他人账户数据（IDOR）。

#### 独立复核

证据支持该IDOR漏洞假设。AccountController 的 GET /api/accounts/me 将完全由客户端控制的 X-Account-Id 请求头直接传入 accountService.getCurrentAccount(requesterId)，该路径不使用 Authorization 头、不调用 verifySession，也无任何归属校验。AccountService.getCurrentAccount 仅检查 requesterId 非空后即调用 accountRepository.findById(requesterId) 并直接返回查询结果，未校验该 ID 与已认证会话或调用者归属的关系，构成 CWE-639 对象级授权缺失：攻击者可伪造任意 X-Account-Id 读取对应账户敏感数据。同一证据包中 SessionController/SessionService 表明会话机制仅用于 /api/session/details（verifySession）与 /admin/export（角色检查），反衬 /me 路径无认证，佐证该控制失效。

#### 修复建议

在GET /api/accounts/me到getCurrentAccount返回的当前账户敏感数据（响应体）之间实施并集中复用控制器层无认证与归属校验，直接信任客户端头作为身份标识。

### 4. jndi_injection：待由调用者闭包解析的入口

- 严重性：`high`
- 置信度：`high`
- CWE：CWE-74
- 根因位置：`src/main/java/com/sinkspring/bench/controller/OperationsToolController.java:1`

#### 问题与影响

外部输入可能到达 InitialContext().lookup 且缺少固定JNDI名称白名单

#### 根因

OperationsToolController的GET /api/tools/directory以@RequestParam name直接传入lookupDirectory，后者无任何白名单即执行InitialContext().lookup(name)，外部可控参数完整到达JNDI sink，控制缺失已由源码证明。

#### 攻击路径

外部输入可能到达 InitialContext().lookup 且缺少固定JNDI名称白名单

#### 独立复核

源码证据支持该漏洞假设。OperationsToolController 的 GET /api/tools/directory 将 @RequestParam String name 原样传入 operationsToolService.lookupDirectory(name)（无任何校验、过滤或白名单），OperationsToolService.lookupDirectory 直接执行 new InitialContext().lookup(name) 并将结果字符串化返回。外部可控 HTTP 参数完整到达 JNDI lookup sink，且该路径上不存在固定JNDI名称白名单或任何输入约束，控制失效由两个证据文件逐行直接证明。JNDI 注入分类（CWE-74）与缺少白名单这一根因成立。

#### 修复建议

在待由调用者闭包解析的入口到src/main/java/com/sinkspring/bench/service/OperationsToolService.java 中的 InitialContext().lookup之间实施并集中复用固定JNDI名称白名单。

### 5. ssrf：待由调用者闭包解析的入口

- 严重性：`medium`
- 置信度：`high`
- CWE：CWE-918
- 根因位置：`src/main/java/com/sinkspring/bench/controller/IntegrationController.java:1`

#### 问题与影响

外部输入可能到达 httpClient.send 且缺少目标协议和地址白名单

#### 根因

外部@RequestParam直达loadPreview并HTTP请求任意location，无协议或地址限制。

#### 攻击路径

外部输入可能到达 httpClient.send 且缺少目标协议和地址白名单

#### 独立复核

漏洞假设成立。证据包中的两个文件直接且完整地证明了该路径：IntegrationController.preview 是 @RestController 下的 @GetMapping("/preview") 端点，接收外部可控的 @RequestParam String location，并调用 resourceSyncService.loadPreview(location)；ResourceSyncService.loadPreview 直接以 URI.create(location) 构造 HttpRequest 并调用 httpClient.send，途中没有任何协议（http/https）或主机/地址白名单校验。服务中存在的 catalogLocations 白名单仅用于 loadCatalog，不作用于 loadPreview 路径；该路径上也未发现其他校验或防护。因此"外部输入可达 httpClient.send 且缺少目标协议和地址白名单"由源码证明。

#### 修复建议

在待由调用者闭包解析的入口到src/main/java/com/sinkspring/bench/service/ResourceSyncService.java 中的 httpClient.send之间实施并集中复用目标协议和地址白名单。

### 6. ssrf：待由调用者闭包解析的入口

- 严重性：`medium`
- 置信度：`high`
- CWE：CWE-918
- 根因位置：`src/main/java/com/sinkspring/bench/controller/IntegrationController.java:1`

#### 问题与影响

外部输入可能到达 getResponseCode 且缺少目标协议和地址白名单

#### 根因

RemoteRequest.callback经@RequestBody直达deliverUpdate并发起连接，无校验。

#### 攻击路径

外部输入可能到达 getResponseCode 且缺少目标协议和地址白名单

#### 独立复核

证据支持该SSRF漏洞假设。数据流在证据包内完整可见：IntegrationController 的 POST /api/integrations/updates 以 @RequestBody 接收 RemoteRequest（含无任何校验注解的 callback 字段），调用 resourceSyncService.deliverUpdate(request)；deliverUpdate 直接将 request.getCallback() 传入 URI.create(...).toURL() 打开 HttpURLConnection 并发起 POST，随后调用 connection.getResponseCode()。该路径上不存在协议或地址白名单/校验；ResourceSyncService 中唯一的白名单 catalogLocations 仅用于 loadCatalog，不覆盖 callback 路径。外部输入到达 getResponseCode 且缺少目标校验的假设成立。

#### 修复建议

在待由调用者闭包解析的入口到src/main/java/com/sinkspring/bench/service/ResourceSyncService.java 中的 getResponseCode之间实施并集中复用目标协议和地址白名单。

### 7. sql_injection：待由调用者闭包解析的入口

- 严重性：`high`
- 置信度：`high`
- CWE：CWE-89
- 根因位置：`src/main/java/com/sinkspring/bench/dao/LegacyOrderDAO.java:1`

#### 问题与影响

外部输入可能到达 executeQuery 且缺少参数化SQL

#### 根因

findOrderById将orderId直接拼接SQL，未参数化。

#### 攻击路径

外部输入可能到达 executeQuery 且缺少参数化SQL

#### 独立复核

漏洞假设成立。证据链完整：(1) OrderController 暴露 /api/orders/{orderId}（@PathVariable）、/api/orders/legacy/view（@RequestParam orderId）、/api/orders/process（@RequestBody orderId/action），外部 HTTP 输入直接填充 OrderRequestDTO/OrderContext；(2) OrderService.getOrderDetails→legacyOrderDAO.findOrderById(context)，findOrderById 将 context.getOrderId() 直接字符串拼接进 SQL（"SELECT * FROM orders WHERE order_id = '" + orderId + "'"）后调用 executeQuery；processOrderAction→executeOrderQuery 同样拼接 orderId（action=UPDATE 时生成 UPDATE 语句）；(3) executeQuery 私有方法用 Statement.executeQuery(sql) 执行传入 SQL，全程未使用 PreparedStatement 或参数绑定，也无任何转义/校验。外部输入（orderId、queryType/action）可无阻碍到达敏感 SQL 执行点且未参数化，构成 CWE-89 SQL 注入。candidate_detail 中"待由调用者闭包解析的入口"已由 OrderController 证据解析为上述三个端点，reachability 成立。

#### 修复建议

在待由调用者闭包解析的入口到src/main/java/com/sinkspring/bench/dao/LegacyOrderDAO.java 中的 executeQuery之间实施并集中复用参数化SQL。

### 8. open_redirect：待由调用者闭包解析的入口

- 严重性：`medium`
- 置信度：`high`
- CWE：CWE-601
- 根因位置：`src/main/java/com/sinkspring/bench/controller/NavigationController.java:1`

#### 问题与影响

外部输入可能到达 .location( 且缺少站内目标白名单

#### 根因

continueTo将@RequestParam next直接传给URI.create并放入302 Location，无任何白名单或协议校验。

#### 攻击路径

外部输入可能到达 .location( 且缺少站内目标白名单

#### 独立复核

源码证据直接证明漏洞假设：NavigationController 的 /api/navigation/continue 端点（@RestController + @GetMapping + @RequestParam String next）将外部请求参数 next 直接传给 URI.create(next) 并放入 302 响应的 Location（.location(...)），该路径无任何站内目标白名单或协议/URI 校验，构成 CWE-601 开放重定向。攻击路径（HTTP 请求参数 → URI.create → .location → Location 头）、根因（无白名单/校验）和入口（Spring 注解映射）均由所给源码片段独立证明。同类的 section() 端点使用了 destinations 白名单映射，反衬 continueTo 缺少白名单，佐证而非反驳漏洞假设。

#### 修复建议

在待由调用者闭包解析的入口到src/main/java/com/sinkspring/bench/controller/NavigationController.java 中的 .location(之间实施并集中复用站内目标白名单。

### 9. xss：待由调用者闭包解析的入口

- 严重性：`medium`
- 置信度：`high`
- CWE：CWE-79
- 根因位置：`src/main/java/com/sinkspring/bench/controller/PageController.java:1`

#### 问题与影响

外部输入可能到达 MediaType.TEXT_HTML 且缺少上下文相关HTML编码

#### 根因

GET /api/pages/search 的 query 参数直接拼接进 text/html 响应，未做任何 HTML 编码。

#### 攻击路径

外部输入可能到达 MediaType.TEXT_HTML 且缺少上下文相关HTML编码

#### 独立复核

漏洞假设由源码证据支持。PageController 的 search 端点（@GetMapping(value="/search", produces=MediaType.TEXT_HTML_VALUE)）将攻击者可控的 @RequestParam String query 直接传入 PageService.buildSearchPage，该方法将原始 query 未经任何 HTML 编码地拼接进 HTML 文档（"<html><body><h1>Search</h1><p>Results for " + query + "</p></body></html>"），并以 text/html 内容类型返回。外部输入到达 MediaType.TEXT_HTML 且缺少上下文相关 HTML 编码的链路完整：controller 端点暴露给外部（Spring MVC 公共映射）→ service 无转义拼接 → text/html 响应。对照同文件 buildSearchText 使用 HtmlUtils.htmlEscape 而 buildSearchPage 未使用，可确认编码缺失并非框架自动完成。renderPage 同样将存储的 TITLE/BODY 无编码拼入 HTML，佐证该缺失模式，但非本次主要发现。

#### 修复建议

在待由调用者闭包解析的入口到src/main/java/com/sinkspring/bench/controller/PageController.java 中的 MediaType.TEXT_HTML之间实施并集中复用上下文相关HTML编码。

### 10. xss：待由调用者闭包解析的入口

- 严重性：`medium`
- 置信度：`high`
- CWE：CWE-79
- 根因位置：`src/main/java/com/sinkspring/bench/controller/PageController.java:1`

#### 问题与影响

外部输入可能到达 MediaType.TEXT_HTML 且缺少上下文相关HTML编码

#### 根因

POST /api/pages 保存的 title/body 未经编码即通过 GET /api/pages/{pageId} 的 text/html 响应输出，形成存储型 XSS。

#### 攻击路径

外部输入可能到达 MediaType.TEXT_HTML 且缺少上下文相关HTML编码

#### 独立复核

证据支持该漏洞假设（缺少上下文相关HTML编码的外部输入到达 TEXT_HTML 响应）。三条 text/html 路径均无编码：1) GET /api/pages/search：@RequestParam query 直接拼接进 "<html>...Results for " + query（PageService.buildSearchPage），无任何编码；2) 存储型路径：POST /api/pages 以 @RequestBody 接收攻击者可控的 title/body（PageRequest）并持久化（PageRepository.save，参数化插入），随后 GET /api/pages/{pageId} 通过 renderPage 将数据库中的 TITLE/BODY 原样拼接进 HTML 并以 produces=MediaType.TEXT_HTML_VALUE 返回，全程无 HTML 编码；3) 对照证据 buildSearchText 使用了 HtmlUtils.htmlEscape，但该端点输出的是 TEXT_PLAIN，恰好说明编码仅存在于非 HTML 端点。控制器中未见认证、校验或全局净化控制，入口由 Spring MVC 映射注解（/api/pages/search、/api/pages、/api/pages/{pageId}）直接暴露。存储型 XSS 路径中攻击者自建页面（POST 返回其自控 pageId），端到端可控。

#### 修复建议

在待由调用者闭包解析的入口到src/main/java/com/sinkspring/bench/controller/PageController.java 中的 MediaType.TEXT_HTML之间实施并集中复用上下文相关HTML编码。

### 11. xxe：待由调用者闭包解析的入口

- 严重性：`high`
- 置信度：`high`
- CWE：CWE-611
- 根因位置：`src/main/java/com/sinkspring/bench/service/CatalogImportService.java:1`

#### 问题与影响

外部输入可能到达 .parse(new InputSource 且缺少禁用外部实体和DOCTYPE

#### 根因

CatalogController将外部XML请求体直传importCatalog，且该方法显式启用了外部实体与DOCTYPE，XXE可控成立。

#### 攻击路径

外部输入可能到达 .parse(new InputSource 且缺少禁用外部实体和DOCTYPE

#### 独立复核

证据支持该漏洞假设。CatalogImportService.importCatalog 显式将 disallow-doctype-decl 设为 false、external-general-entities 与 external-parameter-entities 设为 true、setExpandEntityReferences(true)，随后对入参 content 执行 builder.parse(new InputSource(new StringReader(content)))，即外部实体与 DOCTYPE 未被禁用且被主动开启。CatalogController 的 POST /api/catalog/import（consumes=application/xml）以 @RequestBody String content 直接传入 catalogImportService.importCatalog(content)，形成 外部HTTP请求体 → importCatalog → 不安全的 .parse(new InputSource) 的完整数据流，且解析后的 getTextContent() 作为响应返回，外部实体展开结果可回显。XXE（CWE-611）根因、路径与影响均被所给源码证明。

#### 修复建议

在待由调用者闭包解析的入口到src/main/java/com/sinkspring/bench/service/CatalogImportService.java 中的 .parse(new InputSource之间实施并集中复用禁用外部实体和DOCTYPE。

### 12. template_injection：待由调用者闭包解析的入口

- 严重性：`high`
- 置信度：`high`
- CWE：CWE-1336
- 根因位置：`src/main/java/com/sinkspring/bench/controller/OperationsToolController.java:1`

#### 问题与影响

外部输入可能到达 template.process 且缺少固定模板和数据模型隔离

#### 根因

OperationsToolController.previewMessage将请求体template直接传入renderMessage，作为FreeMarker模板源码执行，配置UNRESTRICTED_RESOLVER，构成模板注入。

#### 攻击路径

外部输入可能到达 template.process 且缺少固定模板和数据模型隔离

#### 独立复核

漏洞假设由提供的源码直接证明：OperationsToolController 的 @PostMapping("/messages/preview") 端点把请求体 ToolRequest 中的 template 字段（request.getTemplate()）原样传入 OperationsToolService.renderMessage(source, values)；renderMessage 用该用户可控字符串构造 FreeMarker Template（new Template("message", source, templateConfiguration)）并调用 template.process(values, output)。模板源码既非固定模板也未经任何校验/白名单，数据模型 values 也直接来自请求体，无隔离。且构造函数显式设置 templateConfiguration.setNewBuiltinClassResolver(TemplateClassResolver.UNRESTRICTED_RESOLVER)，即禁用安全的类解析限制，构成 CWE-1336 模板注入路径。候选描述中的占位符入口（"待由调用者闭包解析的入口"）已被控制器证据具体化：外部 HTTP 输入经 POST /api/tools/messages/preview 到达 template.process。入口、传递、sink 三环节均有源码证据，控制失效成立。

#### 修复建议

在待由调用者闭包解析的入口到src/main/java/com/sinkspring/bench/service/OperationsToolService.java 中的 template.process之间实施并集中复用固定模板和数据模型隔离。

### 13. unsafe_deserialization：待由调用者闭包解析的入口

- 严重性：`high`
- 置信度：`high`
- CWE：CWE-502
- 根因位置：`src/main/java/com/sinkspring/bench/service/PreferenceService.java:1`

#### 问题与影响

外部输入可能到达 ObjectInputStream 且缺少安全数据格式和类型白名单

#### 根因

restoreSnapshot 直接对 Base64 解码流调用 ObjectInputStream.readObject()，无类型过滤。

#### 攻击路径

外部输入可能到达 ObjectInputStream 且缺少安全数据格式和类型白名单

#### 独立复核

证据完整证实了漏洞假设。数据流已由源码直接证明：(1) PreferenceController.restore 是 @PostMapping("/restore") 的公开端点，以 @RequestBody 绑定 PreferenceRequest，其 content 字段完全来自 HTTP 请求体（PreferenceRequest.java 仅有该字段，无校验注解）；(2) restore 直接调用 preferenceService.restoreSnapshot(request.getContent())；(3) restoreSnapshot 对 content 做 Base64 解码后直接构造 ObjectInputStream 并调用 readObject()，源码中不存在 ObjectInputFilter、类型白名单或任何安全数据格式校验。因此"外部输入可到达 ObjectInputStream 且缺少安全数据格式和类型白名单"的假设由源码证实，对应 CWE-502 不安全反序列化。候选中的攻击路径、根因（无类型过滤的 readObject）与证据一致；impact 评为 high 基于该类 sink 的标准影响，未动态复现。

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

restoreSnapshot 作为中间 hops 将外部输入传入 ObjectInputStream。

#### 攻击路径

外部输入可能到达 ObjectInputStream 且缺少安全数据格式和类型白名单

#### 独立复核

漏洞假设成立。证据链完整：PreferenceController 的 POST /api/preferences/restore 以 @RequestBody 接收外部可控的 PreferenceRequest.content，直接调用 preferenceService.restoreSnapshot(content)；restoreSnapshot 将 content 经 Base64 解码后，用 ObjectInputStream(ByteArrayInputStream(payload)) 并调用 readObject() 反序列化任意类。PreferenceService 代码中未设置 ObjectInputFilter、未使用 LookaheadObjectInputStream、也无任何类型白名单/安全数据格式校验，readObject 前未对类做任何约束。因此外部输入确实可到达 ObjectInputStream 且缺少类型白名单，构成 CWE-502 不安全反序列化路径。候选中的"待由调用者闭包解析的入口"占位已由控制器证据解析为 /api/preferences/restore 端点。

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

importDesktopProfile 使用 XMLDecoder.readObject() 解析可控 XML，未禁用对象图。

#### 攻击路径

外部输入可能到达 XMLDecoder 且缺少禁用对象图反序列化

#### 独立复核

漏洞假设由源码证据支持。证据链完整：(1) PreferenceController.importDesktop 标注 @PostMapping("/desktop-import") 并以 @RequestBody PreferenceRequest 接收 HTTP 请求体（PreferenceRequest 仅含 String content 字段，无校验）；(2) 该方法直接调用 preferenceService.importDesktopProfile(request.getContent())，无任何过滤或变换；(3) PreferenceService.importDesktopProfile 将 content 以 UTF-8 编码包装为 ByteArrayInputStream 交给 XMLDecoder 并立即调用 readObject()，证据中不存在任何限制 XMLDecoder 实例化对象图的机制（无 filter、无校验、无 SecurityManager 相关代码）。XMLDecoder.readObject() 语义即按攻击者可控 XML 中的 <object> 节点实例化任意类并调用其方法，且 controller 返回 profile.getClass().getName() 与 toString()，表明反序列化结果被直接使用。故"外部输入到达 XMLDecoder 且缺少禁用对象图反序列化"（CWE-502）的核心主张由所提供源码证明。候选描述中"controller 调用代码被截断"的局限已不成立——证据包含完整控制器代码，入口路径可直接闭合。

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

importDesktopProfile 直接将外部内容交给 XMLDecoder.readObject()。

#### 攻击路径

外部输入可能到达 XMLDecoder 且缺少禁用对象图反序列化

#### 独立复核

证据支持漏洞假设。完整外部可达路径可由证据源码证明：(1) PreferenceController 的 @PostMapping("/desktop-import") 以 @RequestBody 接收 PreferenceRequest 并直接以 request.getContent() 调用 PreferenceService.importDesktopProfile（file:d53cf9db…:0:1586），控制器与 DTO 中均无认证/授权注解或输入校验；(2) PreferenceRequest.content 为普通无注解 String（file:51a376f4…:0:125）；(3) importDesktopProfile 将 content 原样 UTF-8 编码为字节流构造 XMLDecoder 并直接调用 readObject() 解析对象图，无任何白名单、校验或过滤（file:63f6505b…:0:1536）。XMLDecoder 本身不提供禁用对象图反序列化的机制（不同于 ObjectInputStream 的 ObjectInputFilter），源码中也无任何缓解措施，因此攻击者可控 XML 可经 readObject() 触发任意类实例化与方法调用（CWE-502）。候选详情的 entry 占位符不影响结论，证据已给出实际入口为 POST /api/preferences/desktop-import。

#### 修复建议

在待由调用者闭包解析的入口到src/main/java/com/sinkspring/bench/service/PreferenceService.java 中的 XMLDecoder之间实施并集中复用禁用对象图反序列化。

### 17. unsafe_deserialization：POST /api/preferences/restore

- 严重性：`high`
- 置信度：`high`
- CWE：CWE-502
- 根因位置：`src/main/java/com/sinkspring/bench/controller/PreferenceController.java:1`

#### 问题与影响

服务端直接反序列化攻击者提供的Java序列化字节流，可实例化任意类导致RCE

#### 根因

POST /restore 经 @RequestBody 将 content 传入 restoreSnapshot 并触发 readObject()，形成完整路径。

#### 攻击路径

服务端直接反序列化攻击者提供的Java序列化字节流，可实例化任意类导致RCE

#### 独立复核

证据链完整支持该漏洞假设。控制器 PreferenceController 以 @RestController @RequestMapping("/api/preferences") 暴露 POST /restore，通过 @RequestBody 接收 PreferenceRequest，将 request.getContent()（攻击者可控字符串）传入 PreferenceService.restoreSnapshot()。restoreSnapshot 对 content 做 Base64 解码后直接构造 ObjectInputStream(new ByteArrayInputStream(payload)) 并调用 readObject()，全程无 ObjectInputFilter、无 resolveClass 白名单/黑名单、无任何输入校验或过滤（已提供完整源码可见）。因此攻击者可控字节流可直达 ObjectInputStream.readObject() 危险 sink，服务端会从流中实例化类路径上的可序列化类，构成 CWE-502 不安全反序列化。

#### 修复建议

在POST /api/preferences/restore到ObjectInputStream.readObject()之间实施并集中复用未知：restoreSnapshot是否配置resolveClass类名白名单/黑名单。

### 18. xss：GET /api/pages/search?query=

- 严重性：`medium`
- 置信度：`high`
- CWE：CWE-79
- 根因位置：`src/main/java/com/sinkspring/bench/controller/PageController.java:1`

#### 问题与影响

未转义的query直接嵌入HTML响应，构成反射型XSS

#### 根因

buildSearchPage将query未转义直接拼接HTML并返回TEXT_HTML，形成反射型XSS。

#### 攻击路径

未转义的query直接嵌入HTML响应，构成反射型XSS

#### 独立复核

漏洞假设成立。证据链完整：PageController.search 将 @RequestParam String query 原样传入 pageService.buildSearchPage(query)，而 PageService.buildSearchPage 直接执行字符串拼接 "<html>...Results for " + query + "</p></body></html>"，未做任何 HTML 转义；控制器以 produces = MediaType.TEXT_HTML_VALUE 声明，返回字符串按 text/html 写入 HTTP 响应体。同文件 buildSearchText 使用 HtmlUtils.htmlEscape(query) 形成对比，证明转义可用但未应用于 buildSearchPage，且无模板引擎自动转义迹象。攻击者可通过 GET /api/pages/search?query=<script>... 将脚本注入响应并被浏览器按 HTML 解析执行，构成反射型 XSS（CWE-79）。未发现否定该路径的有效反证。

#### 修复建议

在GET /api/pages/search?query=到HTTP响应体中未转义的HTML片段之间实施并集中复用未知：buildSearchPage是否对输入执行HTML转义或经模板自动转义。

### 19. xss：GET /api/pages/{pageId}

- 严重性：`medium`
- 置信度：`high`
- CWE：CWE-79
- 根因位置：`src/main/java/com/sinkspring/bench/controller/PageController.java:1`

#### 问题与影响

pageId或存储页面内容未转义嵌入HTML，形成反射/存储型XSS

#### 根因

renderPage将数据库title/body未转义拼接HTML，经POST /api/pages保存恶意内容可构成存储型XSS；pageId仅用于查询不直接输出。

#### 攻击路径

pageId或存储页面内容未转义嵌入HTML，形成反射/存储型XSS

#### 独立复核

源码证据证明控制失效：PageController.page 以 TEXT_HTML 返回 renderPage 的结果；PageService.renderPage 将数据库 TITLE、BODY 未经任何转义直接拼接进 HTML（与同一文件中 buildSearchText 使用 HtmlUtils.htmlEscape 形成对照，说明此处确实缺失转义）。POST /api/pages 的 save 经参数化 MERGE 把任意 title/body 原样入库，GET /api/pages/{pageId} 渲染该内容，构成存储型 XSS 的完整数据路径。注：pageId 仅作为查询键使用，未回显到响应体，故“反射型 XSS 经 pageId”的子主张不被代码支持；实际成立的是经 POST 保存恶意内容触发的存储型 XSS，candidate 的 rootCause 亦如此表述。漏洞假设整体成立。

#### 修复建议

在GET /api/pages/{pageId}到HTML响应体中的页面片段之间实施并集中复用未知：renderPage是否转义pageId及存储的页面内容。

### 20. arbitrary_file_write：POST /api/documents/content

- 严重性：`high`
- 置信度：`high`
- CWE：CWE-73
- 根因位置：`src/main/java/com/sinkspring/bench/controller/DocumentController.java:1`

#### 问题与影响

若storeDocument采用请求中的路径/文件名字段拼接目标路径，攻击者可越界写入或覆盖任意文件（任意文件写入/不安全上传）。

#### 根因

DocumentController将请求体直接传给DocumentService.storeDocument，而storeDocument用request.getPath()与documentRoot.resolve拼接且未做路径规范化。

#### 攻击路径

若storeDocument采用请求中的路径/文件名字段拼接目标路径，攻击者可越界写入或覆盖任意文件（任意文件写入/不安全上传）。

#### 独立复核

源码直接证明漏洞假设成立。DocumentController.putContent（POST /api/documents/content）将@RequestBody DocumentRequest原样传给documentService.storeDocument(request)；DocumentRequest仅含path和content两个字段（Lombok @Data），二者均可由攻击者控制。storeDocument 中 document = documentRoot.resolve(request.getPath())，未做 normalize() 或 startsWith(root) 包含性校验（对比同文件 loadPublishedDocument 已做此类防护，说明缺失并非设计惯例）；随后对缺失父目录调用 Files.createDirectories 自动创建，并以 StandardOpenOption.CREATE + TRUNCATE_EXISTING 写入 request.getContent()。由于 Path.resolve 对绝对路径参数直接返回其本身，而对含 ../ 的相对路径不做规范化即交给操作系统解析，攻击者可用绝对路径或越界相对路径在文档根目录之外新建或覆盖进程可写的任意文件。问题中“若storeDocument采用请求路径字段拼接目标路径”的前提条件已被源码满足，输入从请求体直达文件写入敏感操作且无有效控制，任意文件写入/覆盖（CWE-73）成立。

#### 修复建议

在POST /api/documents/content到服务器文件系统写入（新建或覆盖文件）之间实施并集中复用控制器未限制写入目录、文件名与文件类型。

### 21. arbitrary_file_write：DocumentService.storeDocument(DocumentRequest)

- 严重性：`high`
- 置信度：`high`
- CWE：CWE-73
- 根因位置：`src/main/java/com/sinkspring/bench/service/DocumentService.java:1`

#### 问题与影响

path 含 ../ 可越界覆写服务器任意文件，content 完全由攻击者控制

#### 根因

storeDocument使用documentRoot.resolve(request.getPath())，未调用normalize或startsWith校验，且会自动创建父目录，攻击者可传../路径覆盖任意文件。

#### 攻击路径

path 含 ../ 可越界覆写服务器任意文件，content 完全由攻击者控制

#### 独立复核

漏洞假设成立。DocumentService.storeDocument 直接执行 documentRoot.resolve(request.getPath()) 而未做 normalize 或 startsWith 校验：若 path 含 ../（或为绝对路径），返回的 Path 保留未规范化段，随后 Files.writeString 按该路径写入，可越过 documentRoot 指向任意可达位置；parent 的 Files.createDirectories 还会自动创建缺失父目录，扩大可写面。写入选项为 CREATE + TRUNCATE_EXISTING，content 原样写入，完全由请求方控制。可达性由 DocumentController.putContent 证明：POST /api/documents/content 经 @RequestBody 直接绑定 DocumentRequest 的 path/content，DTO 无任何校验注解，证据中亦未见认证或输入过滤拦截器。同文件 loadPublishedDocument 的 toRealPath/startsWith 防护未在 storeDocument 路径上调用，反证不存在统一防护。

#### 修复建议

在DocumentService.storeDocument(DocumentRequest)到Files.writeString(document,request.getContent())之间实施并集中复用无 normalize/startsWith 校验且自动创建父目录。

### 22. path_traversal：GET /api/documents/content?name=...

- 严重性：`medium`
- 置信度：`high`
- CWE：CWE-22
- 根因位置：`src/main/java/com/sinkspring/bench/controller/DocumentController.java:1`

#### 问题与影响

若loadDocument未对name做规范化与目录约束，../序列可读取仓库外任意文件（路径穿越）。

#### 根因

控制器直接传参且服务端resolve未规范化，../可越界读文件

#### 攻击路径

若loadDocument未对name做规范化与目录约束，../序列可读取仓库外任意文件（路径穿越）。

#### 独立复核

漏洞假设成立，由源码直接证明：DocumentController.getContent 的 @GetMapping("/content") 将客户端可控的 @RequestParam name 无任何校验直接传入 documentService.loadDocument(name)；DocumentService.loadDocument 执行 documentRoot.resolve(name) 后直接 Files.readString(document)，既未调用 normalize()，也无 startsWith/toRealPath 目录包含检查，因此 name 含 ../ 序列（如 ../../etc/passwd）可解析到 documentRoot（java.io.tmpdir/sinkspring-documents）之外并读取文件内容，控制器再以 TEXT_PLAIN 将读取内容返回客户端。同文件中的 loadPublishedDocument 实现了 normalize + toRealPath + startsWith 三重防护，反衬 loadDocument 缺少同等约束，且该端点未走 loadPublishedDocument 的防护路径。用户所述前提（loadDocument 未做规范化与目录约束）与源码一致。

#### 修复建议

在GET /api/documents/content?name=...到服务器文件内容经TEXT_PLAIN响应返回客户端之间实施并集中复用控制器无路径校验，服务端规范化与白名单逻辑未知。

### 23. path_traversal：DocumentService.loadDocument(String name)

- 严重性：`medium`
- 置信度：`high`
- CWE：CWE-22
- 根因位置：`src/main/java/com/sinkspring/bench/controller/DocumentController.java:1`

#### 问题与影响

name 含 ../ 或绝对路径时可越界读取服务器任意文本文件

#### 根因

name来自请求且loadDocument无任何边界校验，路径穿越成立

#### 攻击路径

name 含 ../ 或绝对路径时可越界读取服务器任意文本文件

#### 独立复核

源码证据支持该漏洞假设。DocumentController.getContent 将未校验的 @RequestParam "name" 直接传入 DocumentService.loadDocument；loadDocument 仅执行 documentRoot.resolve(name) 后即调用 Files.readString(document, UTF_8)，既未 normalize 也未做根目录边界校验。Path.resolve 对绝对路径参数会原样返回该绝对路径（Java NIO 语义），而 ".." 分量由操作系统在读取时解析，因此 ../ 与绝对路径输入均可越出 documentRoot 读取任意可读文本文件，构成 CWE-22 路径穿越。同文件中 loadPublishedDocument 采用 toRealPath+startsWith 防护而 loadDocument 完全没有，恰反证了该控制缺失并非整体防护，且不适用于本方法。

#### 修复建议

在DocumentService.loadDocument(String name)到Files.readString(document)之间实施并集中复用与 loadPublishedDocument 的 toRealPath+startsWith 防护对比，本方法无任何路径约束。

### 24. unsafe_deserialization：POST /api/preferences/desktop-import

- 严重性：`high`
- 置信度：`high`
- CWE：CWE-502
- 根因位置：`src/main/java/com/sinkspring/bench/controller/PreferenceController.java:1`

#### 问题与影响

桌面配置导入对不可信字节流做反序列化，存在与restore同源的RCE面

#### 根因

Controller和Service证据完整证明外部请求体content直达XMLDecoder.readObject，无任何输入或类型约束，构成不安全反序列化。

#### 攻击路径

桌面配置导入对不可信字节流做反序列化，存在与restore同源的RCE面

#### 独立复核

源码证据完整证明攻击路径：POST /api/preferences/desktop-import → PreferenceController.importDesktop(@RequestBody PreferenceRequest) → request.getContent()（无校验、无类型约束）→ PreferenceService.importDesktopProfile → new XMLDecoder(new ByteArrayInputStream(content.getBytes(UTF_8))).readObject()。XMLDecoder.readObject是CWE-502不安全反序列化原语，可通过XML表达实例化任意类并调用任意方法（如ProcessBuilder.start），使用JDK自带类即可构成RCE，不依赖外部Gadget库；与restoreSnapshot(ObjectInputStream)同属对不可信请求体content的反序列化，构成同源RCE面。证据包内路径上未发现任何有效控制（无输入校验、无类型白名单、无SecurityManager）。漏洞假设supported。

#### 修复建议

在POST /api/preferences/desktop-import到反序列化/解析处理器之间实施并集中复用未知：导入格式解析及类型约束。

### 25. unsafe_deserialization：PreferenceService.restoreSnapshot(String content)

- 严重性：`high`
- 置信度：`high`
- CWE：CWE-502
- 根因位置：`src/main/java/com/sinkspring/bench/controller/PreferenceController.java:1`

#### 问题与影响

若content可经HTTP或消息入口到达，则可能通过Gadget链实现远程代码执行。

#### 根因

Controller将外部request.getContent()传入restoreSnapshot，明确为Base64解码后ObjectInputStream.readObject()，无ObjectInputFilter或类型白名单，Source到Sink完整。

#### 攻击路径

若content可经HTTP或消息入口到达，则可能通过Gadget链实现远程代码执行。

#### 独立复核

证据支持漏洞假设。源码链完整：PreferenceController.restore 端点以 @RequestBody 接收 PreferenceRequest 并调用 preferenceService.restoreSnapshot(request.getContent())（controller 证据，HTTP 可达）；PreferenceService.restoreSnapshot 将 content 经 Base64.getDecoder().decode 后交由 new ObjectInputStream(new ByteArrayInputStream(payload)).readObject() 反序列化（service 证据），且该方法内无 ObjectInputFilter、类型白名单或任何输入校验（preventiveControls 为空属实）。因此攻击者可控内容确实到达 ObjectInputStream.readObject() 这一危险反序列化 Sink，构成 CWE-502 不安全反序列化；由此推断"可能通过 Gadget 链实现 RCE"作为该 Sink 的典型后果成立（RCE 可行性本身依赖运行时 classpath 中 Gadget 类，属未证明前提，但不否定反序列化漏洞本身）。Base64 解码使输入必须是合法 Base64，攻击者可轻易构造对应恶意序列化字节流，不构成有效防护。

#### 修复建议

在PreferenceService.restoreSnapshot(String content)到ObjectInputStream.readObject()构造任意对象之间实施并集中复用无类型白名单、无输入校验，完全信任调用方传入内容。

### 26. unsafe_deserialization：PreferenceService.importDesktopProfile(String content)

- 严重性：`high`
- 置信度：`high`
- CWE：CWE-502
- 根因位置：`src/main/java/com/sinkspring/bench/controller/PreferenceController.java:1`

#### 问题与影响

若content来自外部请求，XMLDecoder反序列化可直接导致远程代码执行。

#### 根因

Controller外部输入经importDesktopProfile进入XMLDecoder.readObject，代码证据再现同一入口且无校验，形成完整不安全反序列化链。

#### 攻击路径

若content来自外部请求，XMLDecoder反序列化可直接导致远程代码执行。

#### 独立复核

漏洞假设成立。证据链完整：PreferenceController 中 POST /api/preferences/desktop-import 以 @RequestBody PreferenceRequest 直接接收 HTTP 请求体，未经任何校验将 request.getContent() 传给 PreferenceService.importDesktopProfile(content)；该服务方法将 content 按 UTF-8 转为字节流后直接构造 XMLDecoder 并调用 readObject()。request 的 content 为普通 String 字段，来源为外部请求体，故题设条件"content来自外部请求"由源码满足。XMLDecoder.readObject() 是公认的不安全反序列化汇点（CWE-502），可实例化任意类并调用方法（如 ProcessBuilder/Runtime.exec），攻击者可控的 XML 输入直接进入该汇点即可触发任意对象构造与方法调用，导致远程代码执行。证据中未发现任何输入校验、白名单或过滤控件介于外部输入与汇点之间。

#### 修复建议

在PreferenceService.importDesktopProfile(String content)到XMLDecoder.readObject()可触发任意对象构造与方法调用之间实施并集中复用无XML输入校验，XMLDecoder本身支持任意bean标签。

### 27. expression_injection：OperationsToolService.calculate(formula, values)

- 严重性：`high`
- 置信度：`high`
- CWE：CWE-917
- 根因位置：`src/main/java/com/sinkspring/bench/service/OperationsToolService.java:1`

#### 问题与影响

攻击者控制formula时可通过T(java.lang.Runtime).getRuntime().exec执行任意命令。

#### 根因

用户可控formula经RestController直达calculate，使用StandardEvaluationContext无受限调用，可SpEL注入执行命令

#### 攻击路径

攻击者控制formula时可通过T(java.lang.Runtime).getRuntime().exec执行任意命令。

#### 独立复核

源码证据链完整支撑该漏洞假设。OperationsToolController.calculate（POST /api/tools/calculate）将请求体中的 formula 经 ToolRequest.getFormula() 直接传入 OperationsToolService.calculate(formula, values)；该方法创建未受限的 StandardEvaluationContext（无类型/方法/包限制、无输入校验），随后执行 parser.parseExpression(formula).getValue(context)。StandardEvaluationContext 允许 T() 运算符与任意静态方法调用，故攻击者控制的 formula 形如 T(java.lang.Runtime).getRuntime().exec(...) 可导致任意命令执行。calculatePreset 使用 SimpleEvaluationContext.forReadOnlyDataBinding()，但那是另一条使用硬编码预设公式的路径，与本漏洞路径无关，不构成防护。根因（用户可控输入直达未受限 SpEL 求值）、路径（Controller→Service→StandardEvaluationContext.getValue）与影响（RCE）均由所给源码直接证明。

#### 修复建议

在OperationsToolService.calculate(formula, values)到StandardEvaluationContext.getValue允许任意Java类与方法调用之间实施并集中复用无：使用StandardEvaluationContext且未限定类型、方法或包访问。

### 28. template_injection：OperationsToolService.renderMessage(source, values)

- 严重性：`high`
- 置信度：`high`
- CWE：CWE-1336
- 根因位置：`src/main/java/com/sinkspring/bench/service/OperationsToolService.java:1`

#### 问题与影响

攻击者控制模板内容时可通过<#assign x="freemarker.template.utility.Execute"?new()>实现RCE。

#### 根因

用户可控template经previewMessage传入renderMessage，Freemarker配置UNRESTRICTED_RESOLVER且直接new Template并process，可用Execute?new()实现RCE

#### 攻击路径

攻击者控制模板内容时可通过<#assign x="freemarker.template.utility.Execute"?new()>实现RCE。

#### 独立复核

漏洞假设被源码证明。证据链完整：(1) OperationsToolController.previewMessage 将请求体 ToolRequest.getTemplate()（攻击者可控字符串，ToolRequest 无校验注解）直接传入 operationsToolService.renderMessage(source, values)；(2) OperationsToolService 构造函数显式执行 templateConfiguration.setNewBuiltinClassResolver(TemplateClassResolver.UNRESTRICTED_RESOLVER)，未设置任何沙箱或模板限制；(3) renderMessage 用该配置 new Template("message", source, templateConfiguration) 并以 template.process(values, output) 渲染，FreeMarker 模板指令（如 <#assign x="freemarker.template.utility.Execute"?new()>${x("cmd")}）在 UNRESTRICTED_RESOLVER 下可实例化任意类，Execute 类可执行系统命令，构成模板注入→RCE。已给证据中未发现认证、授权、输入校验或沙箱等有效防护。

#### 修复建议

在OperationsToolService.renderMessage(source, values)到template.process按模板指令执行任意类实例化之间实施并集中复用无：UNRESTRICTED_RESOLVER允许模板内直接实例化任意类且无沙箱。

### 29. jwt_verification_bypass：待由调用者闭包解析的入口

- 严重性：`high`
- 置信度：`high`
- CWE：CWE-347
- 根因位置：`src/main/java/com/sinkspring/bench/service/SessionService.java:1`

#### 问题与影响

外部输入可能到达 JWT.decode 且缺少验签后再信任声明

#### 根因

readSession直接JWT.decode不验签，且AccountController.export调用该未验证解码结果

#### 攻击路径

外部输入可能到达 JWT.decode 且缺少验签后再信任声明

#### 独立复核

漏洞假设成立（supported）。证据链完整：AccountController.export（/api/accounts/admin/export）将外部可控的 Authorization 请求头直接传给 sessionService.readSession；readSession 仅调用 JWT.decode(token) 而未执行任何签名校验；随后控制器立即信任解码结果，取出 role 声明传给 accountService.exportAccounts，后者只判断 role 字符串是否为 "ADMIN" 即返回 accountRepository.findAll()。因此攻击者无需持有有效签名即可伪造含 role=ADMIN 声明的令牌，绕过验签触发管理员数据导出（CWE-347）。SessionController.details 使用 verifySession 正确验签，恰好反证同一服务中已具备验签手段而 export 路径未使用。

#### 修复建议

在待由调用者闭包解析的入口到src/main/java/com/sinkspring/bench/service/SessionService.java 中的 JWT.decode之间实施并集中复用验签后再信任声明。

### 30. jwt_verification_bypass：携带Authorization头调用SessionService.readSession的HTTP端点（控制器路由未在证据中）

- 严重性：`high`
- 置信度：`high`
- CWE：CWE-347
- 根因位置：`src/main/java/com/sinkspring/bench/service/SessionService.java:1`

#### 问题与影响

若任一控制器以readSession解码出的role=ADMIN等声明作授权依据，攻击者无需密钥即可自造令牌绕过认证与权限控制。

#### 根因

Authorization头进入readSession未验签解码，role声明直接触发exportAccounts的ADMIN授权判断

#### 攻击路径

若任一控制器以readSession解码出的role=ADMIN等声明作授权依据，攻击者无需密钥即可自造令牌绕过认证与权限控制。

#### 独立复核

证据充分支持漏洞假设。AccountController.export（GET /api/accounts/admin/export，@RestController @RequestMapping("/api/accounts")）直接以Authorization头调用sessionService.readSession(authorization)；SessionService.readSession使用JWT.decode(token)仅解码而不验签、不校验过期，返回的DecodedJWT的role声明被立即传入accountService.exportAccounts(session.getClaim("role").asString())，后者仅以"ADMIN".equals(role)作为授权判断并返回accountRepository.findAll()。攻击者可自造三段式JWT（payload含role=ADMIN、签名任意字节）在无HMAC密钥情况下通过该端点导出全部账户，认证与权限控制确实被绕过。问题中的条件（存在控制器以readSession解码出的role声明作授权依据）已被源码证明为真。

#### 修复建议

在携带Authorization头调用SessionService.readSession的HTTP端点（控制器路由未在证据中）到JWT.decode()产出未经验证的DecodedJWT并流入后续授权决策之间实施并集中复用readSession内部无任何验证逻辑，仅verifySession使用HMAC256校验且两者调用关系未知。

### 31. xxe：POST /api/catalog/import (application/xml)

- 严重性：`high`
- 置信度：`high`
- CWE：CWE-611
- 根因位置：`src/main/java/com/sinkspring/bench/controller/CatalogController.java:1`

#### 问题与影响

若XML解析器未禁用DOCTYPE与外部实体，攻击者可通过恶意XML触发XXE读取服务器文件或探测内网。

#### 根因

CatalogController将@RequestBody XML直接传入importCatalog；该方法显式关闭DOCTYPE禁用并启用外部实体，可触发XXE

#### 攻击路径

若XML解析器未禁用DOCTYPE与外部实体，攻击者可通过恶意XML触发XXE读取服务器文件或探测内网。

#### 独立复核

源码直接证明漏洞假设成立。CatalogController 的 @PostMapping("/import", consumes=APPLICATION_XML_VALUE) 将 @RequestBody String content 原样传入 catalogImportService.importCatalog(content)，该服务方法显式执行 factory.setFeature("disallow-doctype-decl", false)、setFeature("external-general-entities", true)、setFeature("external-parameter-entities", true) 及 setExpandEntityReferences(true)，即明确允许DOCTYPE与外部实体展开，且未设置 ACCESS_EXTERNAL_DTD 限制。解析后 document.getDocumentElement().getTextContent() 包含展开的实体文本，经控制器 Map.of("content", ...) 反射回HTTP响应，形成外部实体内容回显，可读取服务器文件（file://）或触发内网请求（http://）。入口可达（无认证代码），输入到敏感解析操作的路径完整，根因、路径与影响均由所给两个源文件证明。

#### 修复建议

在POST /api/catalog/import (application/xml)到外部实体展开导致服务器文件读取或内网SSRF之间实施并集中复用控制器未做任何XML安全配置，解析器DOCTYPE与外部实体策略未知。

### 32. xxe：CatalogImportService.importCatalog(content)

- 严重性：`high`
- 置信度：`high`
- CWE：CWE-611
- 根因位置：`src/main/java/com/sinkspring/bench/controller/CatalogController.java:1`

#### 问题与影响

攻击者可控XML携带DOCTYPE+外部实体时可读取本地文件或发起SSRF。

#### 根因

Controller直接将请求体传给importCatalog，且该方法显式开启外部实体扩展，XXE成立

#### 攻击路径

攻击者可控XML携带DOCTYPE+外部实体时可读取本地文件或发起SSRF。

#### 独立复核

证据支持该漏洞假设。调用链完整且已由源码证明：CatalogController.importCatalog(@RequestBody String content) 将HTTP请求体（application/xml）未做任何校验直接传给 CatalogImportService.importCatalog(content)；该方法显式 setFeature(disallow-doctype-decl, false)、启用 external-general-entities 与 external-parameter-entities、并 setExpandEntityReferences(true)，随后 DocumentBuilder.parse(new InputSource(new StringReader(content))) 展开XML实体，getDocumentElement().getTextContent() 将展开结果经控制器 Map.of("content", ...) 回显给攻击者。因此攻击者可控XML可携带DOCTYPE与外部实体（如 file:///etc/passwd 或 http://内网地址），实现本地文件读取（内容回显）与SSRF，符合CWE-611。无认证/授权、内容校验或XML防护证据存在于该路径上。

#### 修复建议

在CatalogImportService.importCatalog(content)到DocumentBuilder.parse对含DOCTYPE与外部实体的XML进行实体展开之间实施并集中复用无：XXE防护特性被显式关闭且content无任何校验。

### 33. hardcoded_secret：源码仓库/配置文件读取

- 严重性：`medium`
- 置信度：`high`
- CWE：CWE-798
- 根因位置：`src/main/resources/application.yml:1`

#### 问题与影响

生产OAuth凭据随代码分发，仓库或工件泄露即被冒用

#### 根因

application.yml明文含生产client-secret，ResourceSyncService注入后作为请求头发出，无加密或外部密钥管理

#### 攻击路径

生产OAuth凭据随代码分发，仓库或工件泄露即被冒用

#### 独立复核

证据支持该漏洞假设。application.yml（位于 src/main/resources，随源码与构建工件分发）明文包含 client-id: sinkspring-production 与 client-secret: dh_live_Q7m4pN8xK2vL6sR9；ResourceSyncService 通过 @Value 注入该密钥，并在 loadCatalog 出站请求中以 X-Client-Id/X-Client-Secret 请求头实际使用，证明该密钥在运行路径中被用于远端服务鉴权且以明文形式随代码分发。攻击者获得仓库或工件即可读取该凭据，无需任何服务端入口。证据包内未见加密、外部密钥管理或占位符机制可否定该结论；密钥是否仍被远端 document-hub 接受属外部有效性限制，不否定硬编码密钥这一核心问题。

#### 修复建议

在源码仓库/配置文件读取到版本库中的静态配置字符串之间实施并集中复用无（明文硬编码，未见密钥管理或加密）。

### 34. security_misconfiguration：携带Authorization头调用SessionService.verifySession的受保护HTTP端点（控制器路由未在证据中）

- 严重性：`medium`
- 置信度：`high`
- CWE：CWE-16
- 根因位置：`src/main/java/com/sinkspring/bench/service/SessionService.java:1`

#### 问题与影响

静态密钥使持有源码或反编译产物者可离线伪造任意过期不受限的令牌，且固定ACC-9001/ADMIN声明导致会话无法区分角色与主体，属会话与授权设计缺陷。

#### 根因

SessionService中SIGNING_KEY为硬编码常量，openSession固定签发subject=ACC-9001且role=ADMIN，伪造令牌可行。

#### 攻击路径

静态密钥使持有源码或反编译产物者可离线伪造任意过期不受限的令牌，且固定ACC-9001/ADMIN声明导致会话无法区分角色与主体，属会话与授权设计缺陷。

#### 独立复核

漏洞假设的核心主张均可由源码直接复核：(1) SessionService.java中SIGNING_KEY为硬编码字符串常量"sinkspring-session-key"，openSession以同一常量用HMAC256签发固定subject=ACC-9001、role=ADMIN、8小时过期的令牌；verifySession仅执行JWT.require(Algorithm.HMAC256(SIGNING_KEY)).build().verify(token)，无issuer/audience/subject/过期强度约束。持有源码或反编译产物者可离线用该公开常量构造任意声明、任意过期的合法签名令牌并通过verifySession——根因成立。(2) 所有合法会话声明固定为ACC-9001/ADMIN，无法区分角色与主体，会话/授权设计缺陷成立。(3) verifySession的被证调用方为SessionController的GET /api/session/details（证据在包内），伪造令牌可被接受并回显subject/role。结论：漏洞假设（静态密钥离线伪造+固定声明导致无法区分角色主体）supported；但候选对受影响面与路由证据的表述有出入（见counterevidence），实际敏感操作影响未被证据完全支持。

#### 修复建议

在携带Authorization头调用SessionService.verifySession的受保护HTTP端点（控制器路由未在证据中）到verifySession返回的DecodedJWT用于身份确认，但密钥为硬编码常量且声明固定之间实施并集中复用存在签名校验，但密钥静态、所有会话均为单一ADMIN角色、无租户或权限粒度。

### 35. sensitive_data_exposure：任意可触发异常的HTTP请求（如畸形参数或非法JSON）

- 严重性：`medium`
- 置信度：`high`
- CWE：未分类
- 根因位置：`src/main/resources/application.yml:1`

#### 问题与影响

攻击者通过触发异常即可获得内部类名、SQL片段、文件路径等调试信息

#### 根因

include-stacktrace与include-message均为always，默认错误响应会回显堆栈与原始异常消息，静态配置缺陷成立

#### 攻击路径

攻击者通过触发异常即可获得内部类名、SQL片段、文件路径等调试信息

#### 独立复核

配置证据直接证明控制失效：application.yml 将 server.error.include-message 与 server.error.include-stacktrace 均设为 always。按 Spring Boot 默认错误处理（BasicErrorController/DefaultErrorAttributes）的文档化语义，任何未捕获异常的错误响应将无条件携带异常消息与完整堆栈，堆栈必然暴露内部类名、方法名与文件路径，异常消息可能含 SQL 片段等调试细节。包内未见任何剥离敏感字段的缓解控制（无全局异常处理器/过滤器证据），故"触发异常即可在 HTTP 错误响应中获得调试信息"的漏洞假设在配置层面成立。未声明动态复现。

#### 修复建议

在任意可触发异常的HTTP请求（如畸形参数或非法JSON）到HTTP错误响应体之间实施并集中复用无（配置无条件开启，未见过滤器剥离敏感字段）。

### 36. security_misconfiguration：ResourceSyncService中@Value("${partners.document-hub.client-id/client-secret}")注入点

- 严重性：`medium`
- 置信度：`high`
- CWE：CWE-16
- 根因位置：`src/main/java/com/sinkspring/bench/service/ResourceSyncService.java:1`

#### 问题与影响

若配置文件明文保存高权限凭据且目标为占位域名，则存在凭据泄露与误投递风险。

#### 根因

application.yml明文保存dh_live_正式密钥，注入并随出站请求头发往example.com，构成明文凭据误投递配置缺陷。

#### 攻击路径

若配置文件明文保存高权限凭据且目标为占位域名，则存在凭据泄露与误投递风险。

#### 独立复核

源码证据证实假设的两个前提与完整数据流：(1) 已批准配置 application.yml 明文存放 partners.document-hub.client-secret=dh_live_Q7m4pN8xK2vL6sR9 及 client-id=sinkspring-production；(2) ResourceSyncService 通过 @Value 注入两字段，loadCatalog 将其作为 X-Client-Id/X-Client-Secret 请求头附加到 catalogLocations 中固定的 example.com（占位域名）端点；(3) IntegrationController 的 GET /api/integrations/catalogs/{catalog} 直接调用 loadCatalog，可触发该携带凭据的出站请求（catalog 须匹配 Map 键 products/shipping）。两前提均获源码证实，凭据明文入库且自动投递至非应用受控的占位域名，凭据泄露与误投递风险成立；medium 评级合理，因凭据置于 HTTPS 请求头、未回传给触发调用方，实际披露对象为 IANA 运营的 example.com。明文密钥提交于仓库本身亦构成独立凭据暴露面。

#### 修复建议

在ResourceSyncService中@Value("${partners.document-hub.client-id/client-secret}")注入点到出站HTTP请求头明文携带生产凭据之间实施并集中复用值来源为已批准配置文件且出站目标被Map固定。

## 待独立复核候选

### security_misconfiguration：待由调用者闭包解析的入口

外部输入可能到达 include-stacktrace 且缺少生产响应禁用堆栈信息

- 调查编号：`investigation-1`
- 建议严重性：`medium`

### security_misconfiguration：src/main/resources/application.yml

配置 management-exposure-wildcard 可能扩大生产攻击面

- 调查编号：`investigation-2`
- 建议严重性：`medium`

### security_misconfiguration：src/main/resources/application.yml

配置 h2-console-enabled 可能扩大生产攻击面

- 调查编号：`investigation-3`
- 建议严重性：`medium`

### security_misconfiguration：/sinkspring/actuator/env、/actuator/heapdump、/actuator/beans等

全量暴露的Actuator端点导致配置、堆转储与内部结构信息泄露

- 调查编号：`investigation-38`
- 建议严重性：`medium`

### security_misconfiguration：未认证 GET /sinkspring/actuator/{env,beans,heapdump,configprops,...}

env/heapdump 等端点会泄露数据库口令、客户端密钥与运行环境信息

- 调查编号：`investigation-39`
- 建议严重性：`medium`

### hardcoded_secret：application.yml（源码与构建产物）

硬编码数据库口令配合开启的H2控制台导致未授权数据库访问

- 调查编号：`investigation-41`
- 建议严重性：`medium`

### hardcoded_secret：读取 src/main/resources/application.yml 中的 spring.datasource 配置段

数据库口令既随仓库分发又可通过 Actuator 端点二次泄露

- 调查编号：`investigation-42`
- 建议严重性：`medium`

## 未决问题

- 最终发现仅包含独立复核支持的候选；覆盖限制见确定性报告。

## 覆盖与限制

完整安全审计：`false`

- 仍有入口、敏感操作或配置发现包未成功处理
- 仍有路径验证包未完成
- 仍有路径草稿未形成可复核结论
- 仍有未收口的调查、基线问题或候选复核
- 仍有未完成安全审阅声明的文件
- 独立基线尚未提交调查问题
- 尚未建立结构化威胁模型

静态分析结果均需复核；导出不表示完整覆盖或动态复现。可能包含敏感源码，请勿公开上传。
