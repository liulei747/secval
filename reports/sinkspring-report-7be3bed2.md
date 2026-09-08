# Secval 安全审计报告

- 任务 ID：`7be3bed277594fd88a50a835e863451d`
- 状态：`needs_review`
- 报告收口：`partial_report`

## 执行摘要

本次审计经独立静态复核确认 24 条正式安全发现，最高严重性为 high。xss：GET /api/pages/search?query= → PageController.search；hardcoded_secret：POST /api/session/login；xxe：POST /api/catalog/import (application/xml)；function_level_authorization：PATCH /api/accounts/{accountId}/role；sql_injection：GET /api/orders/{orderId} → OrderController.getOrderById；另有 19 条。每条发现均在下文列出根因位置、攻击路径、复核结论和修复建议；未覆盖范围与静态分析限制见“覆盖与限制”。

## 安全发现

### 1. xss：GET /api/pages/search?query= → PageController.search

- 严重性：`medium`
- 置信度：`high`
- CWE：CWE-79
- 根因位置：`src/main/java/com/sinkspring/bench/controller/PageController.java:1`

#### 问题与影响

搜索词未经HTML转义拼入页面导致反射型XSS。

#### 根因

PageController.search将query直接传入PageService.buildSearchPage，后者以字符串拼接方式将query插入HTML并以TEXT_HTML返回，无任何HTML转义，构成反射型XSS。

#### 攻击路径

搜索词未经HTML转义拼入页面导致反射型XSS。

#### 独立复核

源码证据支持该漏洞假设。PageController.search 接收攻击者可控的 @RequestParam query，直接调用 PageService.buildSearchPage(query)；后者以字符串拼接将 query 原样嵌入 HTML（"<p>Results for " + query + "</p>"），无任何 HTML 转义或过滤；控制器以 produces=MediaType.TEXT_HTML_VALUE 声明，@RestController 对 String 返回值按 text/html 原样写入响应体，Spring 默认不对该返回值做 HTML 编码。同一 PageService 中 buildSearchText 对 query 使用 HtmlUtils.htmlEscape，反衬 /search 的 HTML 输出路径缺少转义。攻击者提交含 <script> 等载荷的 query 即被反射进 text/html 响应体，构成 CWE-79 反射型 XSS。证据包内未发现该路径存在任何输出编码、输入过滤或 CSP 等防护，攻击者无需任何权限。

#### 修复建议

在GET /api/pages/search?query= → PageController.search到TEXT_HTML响应体中的未转义query之间实施并集中复用控制器无输出编码或CSP头。

### 2. hardcoded_secret：POST /api/session/login

- 严重性：`medium`
- 置信度：`high`
- CWE：CWE-798
- 根因位置：`src/main/java/com/sinkspring/bench/service/SessionService.java:1`

#### 问题与影响

JWT 使用硬编码或弱密钥签名，攻击者可离线伪造任意 token。

#### 根因

SessionService中硬编码常量SIGNING_KEY并直接用于HMAC256签名，攻击者可离线伪造任意ADMIN token。

#### 攻击路径

JWT 使用硬编码或弱密钥签名，攻击者可离线伪造任意 token。

#### 独立复核

漏洞假设"JWT 使用硬编码或弱密钥签名，攻击者可离线伪造任意 token"由源码直接证明成立。(1) SessionService.java 第17行定义编译期常量 `private static final String SIGNING_KEY = "sinkspring-session-key";`，为字面量硬编码，非从配置/环境读取，application.yml 中亦无任何 JWT 密钥配置项，不存在覆盖途径。(2) 该密钥同时用于签名 `Algorithm.HMAC256(SIGNING_KEY)`（openSession）和验签 `JWT.require(Algorithm.HMAC256(SIGNING_KEY)).verify(token)`（verifySession），验签仅校验签名有效、无额外 claim 约束，因此掌握密钥者可离线构造任意 subject/role/过期时间 的 token 并通过 `/api/session/details` 的验签。(3) 密钥为约21字符的字典化可读字符串（sinkspring-session-key），熵低，支持离线暴力推导，即使不依赖源码泄露也可恢复。(4) POST /api/session/login（SessionController 第18-20行）确为 token 签发与下发点，与入口/资产声明一致。签名控制因弱密钥而失效，离线伪造 token 的安全问题成立。

#### 修复建议

在POST /api/session/login到JWT token 生成与下发之间实施并集中复用控制器未展示密钥来源，签名强度取决于 Service 实现与配置。。

### 3. xxe：POST /api/catalog/import (application/xml)

- 严重性：`high`
- 置信度：`high`
- CWE：CWE-611
- 根因位置：`src/main/java/com/sinkspring/bench/service/CatalogImportService.java:1`

#### 问题与影响

若importCatalog使用未禁用DOCTYPE与外部实体的解析器，恶意XML可实现XXE读取本地文件或触发SSRF。

#### 根因

importCatalog显式开启DTD与外部实体且未过滤，攻击者可控XML可触发XXE。

#### 攻击路径

若importCatalog使用未禁用DOCTYPE与外部实体的解析器，恶意XML可实现XXE读取本地文件或触发SSRF。

#### 独立复核

漏洞假设由源码直接证实。CatalogImportService.importCatalog 明确将 disallow-doctype-decl 设为 false、external-general-entities 与 external-parameter-entities 设为 true、setExpandEntityReferences(true)，即解析器显式允许 DOCTYPE 与外部实体，且未对该 factory 设置 ACCESS_EXTERNAL_DTD/ACCESS_EXTERNAL_SCHEMA 限制（对比同文件 summarizeCatalog 的加固配置）。CatalogController 的 POST /api/catalog/import 以 consumes=application/xml 接收原始 @RequestBody String content 并无过滤地传入 importCatalog，解析结果 document.getDocumentElement().getTextContent() 直接作为响应体返回，形成攻击者可控 XML→启用外部实体的解析器→文件/网络内容回显的完整路径，满足 XXE 读取本地文件或 SSRF 的前提。同文件 summarizeCatalog 已加固，恰好反衬 importCatalog 未加固。

#### 修复建议

在POST /api/catalog/import (application/xml)到XML文档解析器处理攻击者控制的外部实体之间实施并集中复用控制器层未对XML内容做任何过滤。

### 4. function_level_authorization：PATCH /api/accounts/{accountId}/role

- 严重性：`medium`
- 置信度：`high`
- CWE：CWE-862
- 根因位置：`src/main/java/com/sinkspring/bench/controller/AccountController.java:1`

#### 问题与影响

若changeRole未做管理员或自助修改范围限制，任意用户可修改任意账户角色甚至提升自身权限。

#### 根因

AccountService.changeRole直接调用updateRole，未校验requesterId管理员身份或目标账户范围；DTO的role字段无枚举约束，任意用户可提升任意账户角色。

#### 攻击路径

若changeRole未做管理员或自助修改范围限制，任意用户可修改任意账户角色甚至提升自身权限。

#### 独立复核

证据支持该漏洞假设。控制器层与持久化链路均已在证据中：AccountController.updateRole（PATCH /api/accounts/{accountId}/role）把请求头X-Account-Id、路径变量accountId和请求体role直接传入accountService.changeRole；AccountService.changeRole完全忽略requesterId（既不校验管理员身份，也不校验自助范围accountId==requesterId），且不校验role取值，直接调用accountRepository.updateRole执行"UPDATE accounts SET role = ? WHERE account_id = ?"并持久化。该路由未使用SessionService/JWT验证（对比export和details端点均基于会话），X-Account-Id可任意伪造，因此任意调用者可修改任意账户角色（含设为ADMIN），角色修改并持久化这一敏感操作在控制器/服务层无任何授权控制，构成CWE-862函数级授权缺失。

#### 修复建议

在PATCH /api/accounts/{accountId}/role到修改目标账户角色并持久化之间实施并集中复用控制器层无管理员角色校验。

### 5. sql_injection：GET /api/orders/{orderId} → OrderController.getOrderById

- 严重性：`high`
- 置信度：`high`
- CWE：CWE-89
- 根因位置：`src/main/java/com/sinkspring/bench/controller/OrderController.java:1`

#### 问题与影响

未校验的orderId直接透传至服务层查询，若为SQL拼接则构成SQL注入。

#### 根因

OrderController透传orderId, OrderService.getOrderDetails调用LegacyOrderDAO.findOrderById, 后者将未参数化orderId拼接进SQL并执行

#### 攻击路径

未校验的orderId直接透传至服务层查询，若为SQL拼接则构成SQL注入。

#### 独立复核

漏洞假设被源码证据支持。数据流完整可核：OrderController.getOrderById 将 @PathVariable String orderId 无校验写入 OrderRequestDTO（evidence 1），OrderService.getOrderDetails 经 OrderContextFactory.buildContext 原样拷贝 orderId 至 OrderContext（evidence 2 + OrderContextFactory），LegacyOrderDAO.findOrderById 执行 `String sql = "SELECT * FROM orders WHERE order_id = '" + orderId + "'"` 并用 Statement.executeQuery 执行（evidence 3）。"若为SQL拼接"的前提已成立（字符串拼接而非参数化），拼接值直接进入 Statement.executeQuery，无 PreparedStatement、无转义、无校验。路径变量由外部攻击者直接可控，构成 CWE-89 SQL 注入，impact high 合理。

#### 修复建议

在GET /api/orders/{orderId} → OrderController.getOrderById到OrderService.getOrderDetails内部的SQL查询或数据访问调用之间实施并集中复用控制器无输入校验、参数化提示或认证注解。

### 6. sql_injection：GET /api/orders/legacy/view?orderId= → OrderController.legacyViewOrder

- 严重性：`high`
- 置信度：`high`
- CWE：CWE-89
- 根因位置：`src/main/java/com/sinkspring/bench/controller/OrderController.java:1`

#### 问题与影响

legacy入口可能复用未参数化的遗留查询，orderId构成SQL注入源。

#### 根因

legacyViewOrder透传orderId, handleLegacyRequest构造OrderContext后调用findOrderById, 同样进入拼接SQL执行

#### 攻击路径

legacy入口可能复用未参数化的遗留查询，orderId构成SQL注入源。

#### 独立复核

漏洞假设成立。证据链完整：OrderController.legacyViewOrder 以 @RequestParam String orderId 直接透传（无校验）写入 OrderRequestDTO 并设置 action=VIEW；OrderService.handleLegacyRequest 用该 orderId 构造 OrderContext 并调用 legacyOrderDAO.findOrderById(context)；LegacyOrderDAO.findOrderById 取 context.getOrderId() 直接拼接 SQL "SELECT * FROM orders WHERE order_id = '" + orderId + "'"，经 Statement.executeQuery 执行。全路径无 PreparedStatement、无参数化、无转义、无输入校验，orderId 可控字符串到达敏感 SQL 执行点，构成 CWE-89 SQL 注入。

#### 修复建议

在GET /api/orders/legacy/view?orderId= → OrderController.legacyViewOrder到OrderService.handleLegacyRequest内部查询之间实施并集中复用legacy入口无校验且透传原始参数。

### 7. command_injection：未知入口（需调用链定位调用 executeShellCommand 的组件）

- 严重性：`high`
- 置信度：`high`
- CWE：CWE-78
- 根因位置：`src/main/java/com/sinkspring/bench/handler/NativeProcessHandler.java:1`

#### 问题与影响

若 command 含用户可控内容，shell 元字符可被解释执行，构成 shell 命令注入。

#### 根因

executeShellCommand以sh -c执行拼接命令，BackupService将外部可控的name等参数直接拼入command并调用，构成命令注入。

#### 攻击路径

若 command 含用户可控内容，shell 元字符可被解释执行，构成 shell 命令注入。

#### 独立复核

证据支持命令注入假设。NativeProcessHandler.executeShellCommand（约第105-111行，`{"/bin/sh","-c",command}` 构造于第108行）将 command 作为单个字符串交给 /bin/sh -c 执行，shell 会解释其中的 ;、|、$( )、&& 等元字符；executeCommandSafely 的数组形式仅避免词法拆分，无法阻止已作为 -c 参数传入的字符串被 shell 解释，因此不构成有效防护。调用链闭合：SystemController 的 /api/system/backup、/api/system/backup/quick、/api/system/restore、/api/system/diagnostics 四个 HTTP 端点把用户可控的 backupPath/name/targetPath 传入 BackupService，后者以 String.format 拼入命令并调用 executeShellCommand。净化不充分：formatPath 仅删除 \n\r；validateAndFormat 仅补/去首尾斜杠；sanitizePath 拒绝 ;|&` 与 .. 但未拦截 $( )、$、< >，且 quickBackup 的 name 参数完全不净化即拼入 backup-%s 位置。故外部可控输入可达 /bin/sh -c sink 且无有效防护，构成 CWE-78 命令注入。

#### 修复建议

在未知入口（需调用链定位调用 executeShellCommand 的组件）到/bin/sh -c command 的 shell 拼接执行（NativeProcessHandler.java 第 97-99 行附近）之间实施并集中复用executeCommandSafely 使用数组形式仅避免词法拆分，未阻止 shell 元字符（;、|、$() 等）注入。

### 8. command_injection：GET /api/system/backup/quick

- 严重性：`high`
- 置信度：`high`
- CWE：CWE-78
- 根因位置：`src/main/java/com/sinkspring/bench/controller/SystemController.java:1`

#### 问题与影响

backupName 或 backupPath 被拼入 tar/gzip 命令或文件路径导致命令注入或任意文件写入。

#### 根因

quickBackup的name参数未经过滤直接拼入tar命令并经shell执行，可注入任意命令。

#### 攻击路径

backupName 或 backupPath 被拼入 tar/gzip 命令或文件路径导致命令注入或任意文件写入。

#### 独立复核

漏洞假设得到源码证据支持。SystemController.quickBackup 从 @RequestParam 直接接收 backupPath 与 name，组装为 BackupRequestDTO 后调用 BackupService.performQuickBackup；该方法将 backupPath 经 FileUtils.sanitizePath 过滤后与完全未过滤的 backupName 通过 String.format 拼入 "tar -czf %s/backup-%s.tar.gz /var/data"，再由 NativeProcessHandler.executeShellCommand 以 /bin/sh -c 执行。backupName 无任何过滤，注入如 "x;id" 即可在 shell 中执行任意命令；backupPath 虽被 sanitizePath 拦截 ';'、'|'、'&'、反引号与 '..'，但不拦截 '$()' 命令替换与换行符，仍可注入。命令执行使用字符串拼接并经由 shell 解释，是真实可注入的 sink。控制失效与所调查的命令注入问题均成立。

#### 修复建议

在GET /api/system/backup/quick到OS 命令执行或文件系统写入之间实施并集中复用backupPath/name 无过滤直接透传，压缩方式由服务端硬编码为 gzip。。

### 9. path_traversal：GET /api/documents/content?name=

- 严重性：`medium`
- 置信度：`high`
- CWE：CWE-22
- 根因位置：`src/main/java/com/sinkspring/bench/controller/DocumentController.java:1`

#### 问题与影响

若loadDocument直接拼接name到文件路径且未校验../，攻击者可越界读取服务器任意可读文件。

#### 根因

DocumentController将name直接传入loadDocument，后者resolve后无校验即readString，../可越界读取

#### 攻击路径

若loadDocument直接拼接name到文件路径且未校验../，攻击者可越界读取服务器任意可读文件。

#### 独立复核

漏洞假设由源码证明成立。证据显示：DocumentController.getContent 将 @RequestParam name 直接传入 documentService.loadDocument(name)（无任何预处理）；DocumentService.loadDocument 执行 documentRoot.resolve(name) 后直接 Files.readString(document)，未做 normalize、未做 startsWith 包含校验、无目录白名单，name 中 ../ 或绝对路径均可越界读取 documentRoot 之外、服务器进程可读的文件（OS 在打开文件时解析 ..）。对照同一文件中的 loadPublishedDocument 采用 normalize+toRealPath+startsWith 双重防护，说明防护模式已知但未应用于 loadDocument，反证了本路径缺少校验。攻击入口、数据流（name → loadDocument → resolve → Files.readString）与影响（越界任意可读文件读取）均由提供的两个源码块完整闭合，"直接拼接且未校验../"的前提条件成立。

#### 修复建议

在GET /api/documents/content?name=到以拼接后的路径读取服务器文件之间实施并集中复用控制器层无路径规范化或目录白名单。

### 10. path_traversal：HTTP Controller→Service→DocumentService.loadDocument(上游入口待callers确认)

- 严重性：`medium`
- 置信度：`high`
- CWE：CWE-22
- 根因位置：`src/main/java/com/sinkspring/bench/service/DocumentService.java:1`

#### 问题与影响

name含../序列可越出documentRoot读取服务器任意文本文件

#### 根因

DocumentController证实name来自HTTP参数直达loadDocument，后者缺少toRealPath校验且resolve后直接readString，Source→Sink连通

#### 攻击路径

name含../序列可越出documentRoot读取服务器任意文本文件

#### 独立复核

源码证据完整支持该漏洞假设。边界跨越成立：DocumentService.loadDocument 中 documentRoot 为隔离边界（Path.of(tmpdir,"sinkspring-documents")），而 loadDocument 直接执行 documentRoot.resolve(name) 后立即 Files.readString(document, UTF_8)，既无 normalize()、也无 toRealPath()+startsWith(root) 校验；Java Path.resolve 不会折叠".."段，文件系统在打开时按操作系统语义解析，故 name 含"../"可越出 documentRoot。输入到敏感操作连通：DocumentController.getContent 将 HTTP GET /api/documents/content 的 @RequestParam String name（攻击者可控、无需特权）直接传给 loadDocument(name)，Controller 层无任何过滤。控制缺口与防护意图对比明确：同一 Service 的 loadPublishedDocument 采用 toRealPath()+startsWith(root) 双重校验，反衬 loadDocument 缺少同等控制，说明 documentRoot 确为预期安全边界且该路径未执行校验。影响表述准确：Files.readString 以 UTF-8 读取，越界后可读取进程可读的 UTF-8 文本文件（如 /etc/passwd），受进程权限与 UTF-8 有效性限制，故"任意UTF-8文本文件"表述成立。

#### 修复建议

在HTTP Controller→Service→DocumentService.loadDocument(上游入口待callers确认)到Files.readString越界读取任意UTF-8文本文件之间实施并集中复用无(loadPublishedDocument有toRealPath校验而本方法没有)。

### 11. unsafe_deserialization：POST /api/preferences/restore → PreferenceController.restore

- 严重性：`high`
- 置信度：`high`
- CWE：CWE-502
- 根因位置：`src/main/java/com/sinkspring/bench/controller/PreferenceController.java:1`

#### 问题与影响

攻击者可控content进入反序列化，可能触发gadget链或任意类加载。

#### 根因

控制器将请求体content直接传给restoreSnapshot，服务方法Base64解码后无白名单调用ObjectInputStream.readObject，攻击面完整。

#### 攻击路径

攻击者可控content进入反序列化，可能触发gadget链或任意类加载。

#### 独立复核

证据链完整支持控制失效假设：PreferenceController.restore 以 @RequestBody 绑定 PreferenceRequest 并将 content 传入 preferenceService.restoreSnapshot(content)；PreferenceService.restoreSnapshot 对攻击者可控字符串做 Base64 解码后，用普通 ObjectInputStream（未调用 setObjectInputFilter，无类型白名单/allowlist）调用 readObject()，且控制器方法声明抛 ClassNotFoundException，与任意类反序列化行为一致。这构成可达的未过滤 Java 反序列化 sink（CWE-502）：攻击者可通过 POST /api/preferences/restore 提交任意 Base64 序列化负载，触发任意 Serializable 类的实例化与 readObject 执行。路径、变换、sink 均由源码直接证明。

#### 修复建议

在POST /api/preferences/restore → PreferenceController.restore到restoreSnapshot中的反序列化点（含ClassNotFoundException暗示）之间实施并集中复用控制器无类型白名单或格式校验。

### 12. unsafe_deserialization：POST /api/preferences/desktop-import → PreferenceController.importDesktop

- 严重性：`high`
- 置信度：`high`
- CWE：CWE-502
- 根因位置：`src/main/java/com/sinkspring/bench/controller/PreferenceController.java:1`

#### 问题与影响

桌面配置导入若采用反序列化解析，攻击者可控content可执行任意代码。

#### 根因

content经控制器直接进入importDesktopProfile，服务方法用XMLDecoder.readObject解析且无过滤，可构造任意对象。

#### 攻击路径

桌面配置导入若采用反序列化解析，攻击者可控content可执行任意代码。

#### 独立复核

漏洞假设成立（supported）。源码链完整：PreferenceController.importDesktop 将请求体 PreferenceRequest.content（evidence 51a376）直接透传给 PreferenceService.importDesktopProfile（evidence d53cf9）；服务方法用 XMLDecoder + ByteArrayInputStream(content.getBytes(UTF_8)) 并对解码结果调用 readObject()（evidence 63f6505），未发现任何格式白名单、类过滤或输入校验。XMLDecoder.readObject 本身可实例化任意类并调用任意方法（如直接构造 Runtime/ProcessBuilder 执行命令），因此攻击者可控 content 可触发任意代码执行（CWE-502），影响评级 high 成立。方法返回 Object 的类名与 toString 亦证明内容被完整反序列化。

#### 修复建议

在POST /api/preferences/desktop-import → PreferenceController.importDesktop到importDesktopProfile中的解析或反序列化点之间实施并集中复用控制器无格式白名单。

### 13. unsafe_deserialization：PreferenceService.restoreSnapshot(String content)

- 严重性：`high`
- 置信度：`high`
- CWE：CWE-502
- 根因位置：`src/main/java/com/sinkspring/bench/service/PreferenceService.java:1`

#### 问题与影响

若content来自外部输入，可利用原生Java反序列化gadget链实现RCE。

#### 根因

restoreSnapshot的Base64解码后直接ObjectInputStream.readObject，且controller的/restore端点将请求体content传入，外部可达。

#### 攻击路径

若content来自外部输入，可利用原生Java反序列化gadget链实现RCE。

#### 独立复核

源码证据支持漏洞假设：(1) PreferenceService.restoreSnapshot(String content)完整方法体可见，将content经Base64.getDecoder().decode后直接new ObjectInputStream(new ByteArrayInputStream(payload))并调用readObject()，无ObjectInputFilter、无LookAheadObjectInputStream、无类型白名单，解码与反序列化之间亦无任何校验或限制；(2) PreferenceController的@PostMapping("/restore")以@RequestBody接收PreferenceRequest并直接调用preferenceService.restoreSnapshot(request.getContent())，证明外部HTTP可控输入在无校验情况下到达该无过滤反序列化sink，候选前提"content来自外部输入"由源码直接满足；(3) 依赖中可见Spring/Jackson等组件，项目未对readObject实施防护，符合CWE-502经典可利用前置条件（存在gadget类时可达RCE）。控制失效与外部可达性均由所给源码片段证明。

#### 修复建议

在PreferenceService.restoreSnapshot(String content)到ObjectInputStream.readObject()无类型白名单反序列化任意类之间实施并集中复用无类过滤、无LookAheadObjectInputStream等防护。

### 14. unsafe_deserialization：PreferenceService.importDesktopProfile(String content)

- 严重性：`high`
- 置信度：`high`
- CWE：CWE-502
- 根因位置：`src/main/java/com/sinkspring/bench/service/PreferenceService.java:1`

#### 问题与影响

XMLDecoder可解析含ProcessBuilder等元素的XML，若content外部可控可导致命令执行或文件操作。

#### 根因

importDesktopProfile用XMLDecoder.readObject解析content，controller的/desktop-import端点直接传入请求体content，外部可达。

#### 攻击路径

XMLDecoder可解析含ProcessBuilder等元素的XML，若content外部可控可导致命令执行或文件操作。

#### 独立复核

源码证据支持漏洞假设。路径已闭合：(1) 外部入口——PreferenceController 的 @PostMapping("/desktop-import") 端点将请求体 PreferenceRequest.content 直接传给 preferenceService.importDesktopProfile(request.getContent())，无任何认证注解或输入校验；(2) 敏感操作——PreferenceService.importDesktopProfile 将 content 按 UTF-8 转为字节流后，在无过滤、无白名单、无沙箱的情况下交给 new XMLDecoder(ByteArrayInputStream).readObject() 解析；(3) 影响——XMLDecoder.readObject() 是已知不安全反序列化原语（CWE-502），可依据 XML 中 <object> 元素反射构造任意 Java 对象并通过 <void method="..."> 调用方法，含 java.lang.ProcessBuilder 及 start() 调用的 XML 可实现命令执行。证据文件中未发现任何可阻断该路径的有效防护，故"外部可控 content 经 XMLDecoder 导致命令执行或文件操作"的假设成立，impact high 评级依据充分。

#### 修复建议

在PreferenceService.importDesktopProfile(String content)到XMLDecoder.readObject()反射构造任意Java对象并执行构造逻辑之间实施并集中复用无沙箱或XML过滤。

### 15. jwt_verification_bypass：GET /api/accounts/admin/export

- 严重性：`high`
- 置信度：`high`
- CWE：CWE-347
- 根因位置：`src/main/java/com/sinkspring/bench/controller/AccountController.java:1`

#### 问题与影响

若readSession未验证JWT签名或允许弱算法/空签名，攻击者可自签admin角色令牌批量导出账户数据。

#### 根因

readSession仅JWT.decode未验签，控制器直接信任role声明，exportAccounts仅按声明值返回全部账户

#### 攻击路径

若readSession未验证JWT签名或允许弱算法/空签名，攻击者可自签admin角色令牌批量导出账户数据。

#### 独立复核

漏洞假设得到源码证明。(1) SessionService.readSession仅调用JWT.decode(token)解析令牌，未调用JWT.require(...).verify，即不验证签名、不校验算法；(2) AccountController的GET /api/accounts/admin/export直接以Authorization头调用readSession并信任session.getClaim("role").asString()；(3) AccountService.exportAccounts仅校验role字符串等于"ADMIN"后返回accountRepository.findAll()。三者串联，攻击者无需签名密钥即可构造header/payload含role=ADMIN的任意三段式JWT（decode不验签），通过export端点导出全部账户数据。问题中的条件前提（readSession未验证JWT签名）已被源码直接证实，条件成立故攻击路径成立。源码中存在verifySession方法（HMAC256验签），但仅被/api/session/details使用，不在export路径上，不构成对该路径的控制。

#### 修复建议

在GET /api/accounts/admin/export到仅凭令牌role声明导出全部账户数据之间实施并集中复用控制器仅信任SessionService解码出的role声明。

### 16. jwt_verification_bypass：SessionService.readSession

- 严重性：`high`
- 置信度：`high`
- CWE：CWE-347
- 根因位置：`src/main/java/com/sinkspring/bench/service/SessionService.java:1`

#### 问题与影响

若控制器用 readSession 判断身份或角色，攻击者可用任意签名甚至伪造 token 冒充 ADMIN

#### 根因

readSession仅JWT.decode，/api/accounts/admin/export实际调用该无验签方法并据role导出全部账户

#### 攻击路径

若控制器用 readSession 判断身份或角色，攻击者可用任意签名甚至伪造 token 冒充 ADMIN

#### 独立复核

漏洞假设由源码直接证明。SessionService.readSession 仅调用 JWT.decode 解码 token，不校验签名与有效期（同文件 verifySession 才有 HMAC256 验签）。AccountController 的 GET /api/accounts/admin/export 实际调用 readSession（而非 verifySession），读取 token 中 role claim 传给 AccountService.exportAccounts，后者仅比较 role 是否为 "ADMIN"，通过则返回 accountRepository.findAll() 全量账户数据。因此攻击者无需有效签名即可伪造 role=ADMIN 的 JWT（HS256 任意签名即可被 decode 成功），实现未授权全量账户导出，构成 JWT 验签绕过（CWE-347）下的授权控制失效与信息泄露。候选根因、调用路径（controller 确实使用 readSession 判断角色）与影响（high）均有证据支撑。

#### 修复建议

在SessionService.readSession到JWT.decode 仅解码不校验签名与有效期之间实施并集中复用类内同时提供 verifySession 做 HMAC256 验签，但 readSession 只调用 JWT.decode。

### 17. jndi_injection：OperationsToolService.lookupDirectory

- 严重性：`high`
- 置信度：`high`
- CWE：CWE-74
- 根因位置：`src/main/java/com/sinkspring/bench/service/OperationsToolService.java:1`

#### 问题与影响

若 name 可控，可指向外部 LDAP/RMI 端点触发 JNDI 注入导致远程代码执行

#### 根因

控制器 /api/tools/directory 将 @RequestParam name 直接传入 lookupDirectory 并调用 InitialContext.lookup，且无协议白名单或过滤，构成可利用 JNDI 注入。

#### 攻击路径

若 name 可控，可指向外部 LDAP/RMI 端点触发 JNDI 注入导致远程代码执行

#### 独立复核

证据证实漏洞假设的控制失效与攻击路径成立。OperationsToolController.directoryEntry 以 @GetMapping("/directory") 暴露端点，将 @RequestParam String name 直接传入 operationsToolService.lookupDirectory(name)（证据 ce831718...），Service 中 lookupDirectory 无任何校验即执行 new InitialContext().lookup(name) 并返回 String.valueOf(entry)（证据 fb5025bd...）。源码中从 HTTP 请求参数到 InitialContext.lookup 之间不存在协议白名单、前缀过滤（java:/ldap:/rmi: 均未限制）或输入校验，"name 可控"的前提由 @RequestParam 绑定直接证明，用户可提交 ldap:///rmi:// 等外部 JNDI 名称触发注入，构成 JNDI 注入敏感操作。

#### 修复建议

在OperationsToolService.lookupDirectory到javax.naming.InitialContext.lookup(name)之间实施并集中复用无 JNDI 名称前缀或协议白名单，java:/ldap:/rmi: 均未限制。

### 18. template_injection：OperationsToolService.renderMessage

- 严重性：`high`
- 置信度：`high`
- CWE：CWE-1336
- 根因位置：`src/main/java/com/sinkspring/bench/service/OperationsToolService.java:1`

#### 问题与影响

若 source 可控，可利用 FreeMarker 类解析与内建指令执行任意 Java 代码

#### 根因

FreeMarker配置UNRESTRICTED_RESOLVER，renderMessage直接用可控source构造Template并process，previewMessage将请求体template传入，Source到Sink完整且无沙箱防护。

#### 攻击路径

若 source 可控，可利用 FreeMarker 类解析与内建指令执行任意 Java 代码

#### 独立复核

漏洞假设成立（supported）。证据证明：1) OperationsToolService 构造函数将 FreeMarker Configuration 的 new-builtin 类解析器设为 TemplateClassResolver.UNRESTRICTED_RESOLVER（无沙箱限制）；2) renderMessage(String source, Map<String,Object> values) 直接用该 source 构造 new Template("message", source, templateConfiguration) 并 template.process(values, output)，source 即模板内容；3) OperationsToolController 的 POST /api/tools/messages/preview 将 @RequestBody ToolRequest 的 template 字段（ToolRequest 中为 String 模板字段，Lombok @Data 生成 getter）直接传入 renderMessage，无任何校验或过滤。因此攻击者可控的模板源码进入未受限的 FreeMarker 渲染：可通过 ?new() 内建实例化 freemarker.template.utility.Execute 等任意类（如 <#assign x="freemarker.template.utility.Execute"?new()>${x("cmd")}），实现任意 Java 代码/命令执行。Source→Sink 数据流完整，CWE-1336 模板注入成立，影响评级 high 与证据相符。

#### 修复建议

在OperationsToolService.renderMessage到FreeMarker 模板渲染（TemplateClassResolver.UNRESTRICTED_RESOLVER）之间实施并集中复用模板配置启用 UNRESTRICTED_RESOLVER 且未设置沙箱限制。

### 19. expression_injection：OperationsToolService.calculate

- 严重性：`high`
- 置信度：`high`
- CWE：CWE-917
- 根因位置：`src/main/java/com/sinkspring/bench/service/OperationsToolService.java:1`

#### 问题与影响

若 formula 来自外部请求且未过滤，可注入 T(java.lang.Runtime) 类引用实现任意代码执行

#### 根因

OperationsToolController.calculate将请求体formula直接传入calculate，未过滤即进入StandardEvaluationContext求值

#### 攻击路径

若 formula 来自外部请求且未过滤，可注入 T(java.lang.Runtime) 类引用实现任意代码执行

#### 独立复核

漏洞假设成立。证据链完整：OperationsToolController.calculate 为 @PostMapping("/api/tools/calculate")，将 @RequestBody ToolRequest 的 getFormula() 直接传入 operationsToolService.calculate（未过滤、无白名单）；ToolRequest 定义证实 formula 为请求体直接绑定的 String 字段（Lombok @Data）。OperationsToolService.calculate 使用 StandardEvaluationContext（而非 SimpleEvaluationContext），对 formula 执行 parser.parseExpression(formula).getValue(context)，无任何输入校验或沙箱。StandardEvaluationContext 允许 T(...) 类型引用与静态方法访问，T(java.lang.Runtime).getRuntime().exec(...) 类表达式可实现任意代码执行。该端点无认证/授权防护迹象（提供的代码中无安全过滤器，CORS 配置为全放开），未认证外部攻击者可达。calculatePreset 使用 SimpleEvaluationContext 且 preset 经 Map 白名单查找，属另一安全路径，不构成对本路径的反证。

#### 修复建议

在OperationsToolService.calculate到StandardEvaluationContext 下的 SpEL 表达式求值之间实施并集中复用当前无公式白名单或沙箱，StandardEvaluationContext 允许任意类引用与静态方法访问。

### 20. ssrf：ResourceSyncService.loadPreview(String location)

- 严重性：`medium`
- 置信度：`high`
- CWE：CWE-918
- 根因位置：`src/main/java/com/sinkspring/bench/controller/IntegrationController.java:1`

#### 问题与影响

若location源自外部输入且方法可达，攻击者可诱导服务端访问内网或云元数据端点并回显，构成SSRF。

#### 根因

控制器@GetMapping/preview的location参数直接传入loadPreview，HttpClient据此构造请求且无白名单

#### 攻击路径

若location源自外部输入且方法可达，攻击者可诱导服务端访问内网或云元数据端点并回显，构成SSRF。

#### 独立复核

漏洞假设获源码证实。IntegrationController.preview 以 @GetMapping("/preview") 公开映射，将 @RequestParam String location 直接传入 ResourceSyncService.loadPreview(location)（外部输入与可达性均成立）。loadPreview 对 location 无协议/主机白名单或任何校验，直接 URI.create(location) 构造 HttpRequest，经 httpClient.send 发起出站 GET，并将 response.body() 通过 Map.of("content", ...) 原样回显给调用方。外部输入→无校验构造任意URI→服务端出站请求→响应体回显的完整链路被证据文件直接证明，构成CWE-918 SSRF。

#### 修复建议

在ResourceSyncService.loadPreview(String location)到httpClient.send向任意外部地址发起HTTP并回显响应体之间实施并集中复用无协议/主机白名单校验，仅设置5秒超时。

### 21. ssrf：ResourceSyncService.deliverUpdate(RemoteRequest request)

- 严重性：`medium`
- 置信度：`high`
- CWE：CWE-918
- 根因位置：`src/main/java/com/sinkspring/bench/controller/IntegrationController.java:1`

#### 问题与影响

若callback可被外部控制，攻击者可使服务端向内网任意端点POST恶意payload，构成SSRF。

#### 根因

/updates接口通过@RequestBody绑定RemoteRequest，callback和payload由请求体控制，deliverUpdate向其POST且无校验

#### 攻击路径

若callback可被外部控制，攻击者可使服务端向内网任意端点POST恶意payload，构成SSRF。

#### 独立复核

源码证据支持该SSRF漏洞假设。(1) 入口：IntegrationController.sendUpdate 以 @PostMapping("/updates") 暴露于 /api/integrations 下，通过 @RequestBody 将请求体直接绑定为 RemoteRequest，方法及类上无鉴权注解。(2) RemoteRequest 为 @Data DTO，含 callback 与 payload 字段，二者均可由请求体完全控制。(3) 敏感操作：ResourceSyncService.deliverUpdate 将 request.getCallback() 经 URI.create(...).toURL() 解析后建立 HttpURLConnection，setRequestMethod("POST")，并把 request.getPayload() 写入输出流，最终 getResponseCode() 触发实际请求；路径中无任何主机/协议白名单、内网/IP 校验，设置的 3 秒连接与读取超时仅约束耗时，不构成对 SSRF 的防护。外部可控的 callback 可驱动服务端向任意主机端口POST任意payload，控制失效与CWE-918影响均由所给源码直接证明，攻击者无需已有权限即可经公开POST接口输入该值。

#### 修复建议

在ResourceSyncService.deliverUpdate(RemoteRequest request)到向任意callback主机端口发起POST并携带payload之间实施并集中复用无主机/协议校验，仅设置3秒连接与读取超时。

### 22. hardcoded_secret：SessionService.openSession 常量区

- 严重性：`medium`
- 置信度：`high`
- CWE：CWE-798
- 根因位置：`src/main/java/com/sinkspring/bench/service/SessionService.java:1`

#### 问题与影响

已知源码即可用固定密钥伪造任意 ADMIN 令牌或直接使用硬编码口令登录

#### 根因

源码硬编码OPERATOR_PASSWORD与HMAC签名密钥，可直接登录或伪造ADMIN令牌。

#### 攻击路径

已知源码即可用固定密钥伪造任意 ADMIN 令牌或直接使用硬编码口令登录

#### 独立复核

源码证据支持该漏洞假设。SessionService 将 OPERATOR_USERNAME("ops-admin")、OPERATOR_PASSWORD("SpringOps#2026") 与 SIGNING_KEY("sinkspring-session-key") 作为私有常量硬编码，并直接用于 openSession() 的明文口令比对及 Algorithm.HMAC256(SIGNING_KEY) 签名，未发现 @Value/环境变量等外部化注入。SessionController 暴露 POST /api/session/login 调用 openSession()，攻击者凭源码可知的固定口令即可登录，获得含 role=ADMIN 声明的合法 JWT；verifySession() 亦使用同一硬编码密钥校验，故掌握源码者可离线伪造任意 subject 的 ADMIN 令牌并通过 /api/session/details 校验。AccountController 的 /api/accounts/admin/export 甚至调用不校验签名的 readSession() 并直接信任 role 声明（任意自签 token 即可通过），进一步佐证 ADMIN 身份可被伪造。该路径从公开登录入口（或直接伪造 token）到达 JWT 签发/校验逻辑，impact=medium 与 CWE-798 归类合理。

#### 修复建议

在SessionService.openSession 常量区到JWT 签发与登录校验逻辑之间实施并集中复用凭据与 HMAC 密钥写死在源码，无环境变量或配置外部化。

### 23. sensitive_data_exposure：POST /api/preferences/restore → PreferenceController.restore

- 严重性：`medium`
- 置信度：`high`
- CWE：未分类
- 根因位置：`src/main/java/com/sinkspring/bench/controller/PreferenceController.java:1`

#### 问题与影响

将反序列化对象的类名与toString直接返回客户端造成内部类型与数据结构泄露。

#### 根因

证据完整证明反序列化对象类名及toString直接写入HTTP响应，无过滤

#### 攻击路径

将反序列化对象的类名与toString直接返回客户端造成内部类型与数据结构泄露。

#### 独立复核

源码证据完整确认该暴露机制：PreferenceController.restore 通过 @RequestBody 接收 PreferenceRequest，取 request.getContent() 调用 preferenceService.restoreSnapshot()；PreferenceService.restoreSnapshot 将 content Base64 解码后用 ObjectInputStream.readObject() 反序列化，返回的 Object 的 getClass().getName() 与 toString() 被直接写入 Map.of("type",...,"value",...) 作为 HTTP 响应体，两处均无过滤或转换。攻击者可控的 content 沿"请求→反序列化→类名/toString→HTTP 响应"路径成立，"反序列化对象类名与 toString 直接返回客户端"这一假设得到源码证明。需注意：序列化流由攻击者提供，回显的类名与 toString 内容基本为攻击者自定数据，该暴露更多起反序列化类存在性/成功性 oracle 作用，且底层不安全反序列化（无类过滤的 readObject）风险更严重；但这不否定本假设所描述的回显行为本身。

#### 修复建议

在POST /api/preferences/restore → PreferenceController.restore到HTTP响应体中的类名与toString内容之间实施并集中复用控制器无敏感信息过滤。

### 24. sensitive_data_exposure：任意触发未捕获异常的 HTTP 请求

- 严重性：`medium`
- 置信度：`high`
- CWE：未分类
- 根因位置：`src/main/resources/application.yml:1`

#### 问题与影响

所有错误响应回显完整堆栈与内部信息，可辅助枚举内部结构并放大其他漏洞的信息泄露。

#### 根因

配置显式开启include-message和include-stacktrace为always，默认错误渲染将回显堆栈

#### 攻击路径

所有错误响应回显完整堆栈与内部信息，可辅助枚举内部结构并放大其他漏洞的信息泄露。

#### 独立复核

漏洞假设（所有错误响应回显完整堆栈与内部信息）由证据直接支持。application.yml 明确设置 server.error.include-message: always 与 server.error.include-stacktrace: always，这是根因控制点的决定性源码证据：Spring Boot 默认错误属性渲染（DefaultErrorAttributes/BasicErrorController）在该配置下会确定性地在错误响应中携带 error message 与完整堆栈（trace），即 CWE-209 敏感信息泄露。sink 行为（响应回显堆栈/消息）由配置语义直接推出，根因成立；同文件还暴露 H2 console、actuator "*" 端点与 MyBatis/DB 配置，暗示存在可产生 4xx/5xx 错误响应的 HTTP 出错面，入口可达性合理。评级 medium（信息泄露、无权限提升证明）与配置证据匹配。综合判定 supported。

#### 修复建议

在任意触发未捕获异常的 HTTP 请求到HTTP 错误响应向客户端回显完整堆栈与内部信息之间实施并集中复用配置显式开启消息与堆栈回显。

## 待独立复核候选

### hardcoded_secret：src/main/resources/application.yml（已批准配置）

生产级数据库口令与第三方 client-secret 明文硬编码，泄露即获得数据库与合作伙伴 API 的完全身份。

- 调查编号：`investigation-23`
- 建议严重性：`medium`

### hardcoded_secret：application.yml partners.document-hub 配置段

生产伙伴密钥硬编码于源码仓库，泄露后可用于伪造对 document-hub 的客户端身份

- 调查编号：`investigation-24`
- 建议严重性：`medium`

### hardcoded_secret：application.yml spring.datasource 配置段

数据库口令硬编码于配置且与 H2 控制台共用，可能被用于未授权数据库访问

- 调查编号：`investigation-25`
- 建议严重性：`medium`

### security_misconfiguration：GET /sinkspring/h2-console（H2 控制台登录页）

H2 控制台开启且凭据明文存在于已批准配置，攻击者可获得数据库完全控制并借助 H2 函数读写服务器文件或执行命令。

- 调查编号：`investigation-28`
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
