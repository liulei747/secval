# Secval 安全审计报告

- 任务 ID：`25824ee8dfe3433ead105b665ea7825f`
- 状态：`needs_review`
- 报告收口：`partial_report`

## 执行摘要

本次审计经独立静态复核确认 22 条正式安全发现，最高严重性为 high。xxe：POST /api/catalog/import (XML)；open_redirect：GET /api/navigation/continue?next=...；xss：GET /api/pages/search?query=；hardcoded_secret：ResourceSyncService通过@Value注入伙伴凭据；unsafe_deserialization：POST /api/preferences/restore；另有 17 条。每条发现均在下文列出根因位置、攻击路径、复核结论和修复建议；未覆盖范围与静态分析限制见“覆盖与限制”。

## 安全发现

### 1. xxe：POST /api/catalog/import (XML)

- 严重性：`high`
- 置信度：`high`
- CWE：CWE-611
- 根因位置：`src/main/java/com/sinkspring/bench/service/CatalogImportService.java:1`

#### 问题与影响

若解析器未禁用DTD与外部实体，则可XXE读取服务器文件或发起SSRF。

#### 根因

importCatalog显式关闭disallow-doctype-decl并开启外部通用/参数实体及实体引用扩展，证据完整证明XXE可利用。

#### 攻击路径

若解析器未禁用DTD与外部实体，则可XXE读取服务器文件或发起SSRF。

#### 独立复核

漏洞假设由源码直接证明。证据1（CatalogImportService.java）显示 importCatalog() 中 DocumentBuilderFactory 显式设置 disallow-doctype-decl=false、external-general-entities=true、external-parameter-entities=true、setExpandEntityReferences(true)，且未设置 ACCESS_EXTERNAL_DTD/SCHEMA 限制——即解析器明确允许DTD并启用外部实体解析，不存在任何缓解。证据2（CatalogController.java）证明攻击者控制的XML请求体经 POST /api/catalog/import（consumes=APPLICATION_XML）→ CatalogController.importCatalog → CatalogImportService.importCatalog 到达该不安全解析器，返回的 textContent 会随 Map.of("content", ...) 反射给客户端，支持通过外部实体读取服务器文件（响应中回显）及SSRF。summarizeCatalog 虽有安全配置，但属于不同方法/端点，不适用于 importCatalog。候选结论（CWE-611 XXE、high影响）与证据一致，supported。

#### 修复建议

在POST /api/catalog/import (XML)到XML解析器处理外部实体之间实施并集中复用无可见安全解析配置。

### 2. open_redirect：GET /api/navigation/continue?next=...

- 严重性：`medium`
- 置信度：`high`
- CWE：CWE-601
- 根因位置：`src/main/java/com/sinkspring/bench/controller/NavigationController.java:1`

#### 问题与影响

攻击者可重定向用户到任意外部站点形成开放重定向

#### 根因

next参数未经任何校验直接作为302 Location，构成开放重定向。

#### 攻击路径

攻击者可重定向用户到任意外部站点形成开放重定向

#### 独立复核

证据包中控制器源码完整自证该路径：GET /api/navigation/continue 将查询参数 next 经 @RequestParam 直接接收，随后未经任何校验即调用 URI.create(next) 并作为 302 响应的 Location 头回显（ResponseEntity.status(302).location(URI.create(next)).build()）。同文件 /section 端点对 destinations 白名单做 null 校验形成对比，证明 /continue 无同类防护。URI.create 仅拒绝格式非法字符串，对合法外部绝对 URL（如 https://evil.example）不构成限制，攻击者可控输入直达 Location 响应头，构成开放重定向（CWE-601）。入口可达性由 @RestController + @RequestMapping("/api/navigation") + @GetMapping("/continue") 注解直接证明，数据流在单一代码块内完整可见。

#### 修复建议

在GET /api/navigation/continue?next=...到HTTP 302响应Location头直接回显攻击者URL之间实施并集中复用无任何校验，next未经处理即进入Location。

### 3. xss：GET /api/pages/search?query=

- 严重性：`medium`
- 置信度：`high`
- CWE：CWE-79
- 根因位置：`src/main/java/com/sinkspring/bench/controller/PageController.java:1`

#### 问题与影响

query 未经编码直接拼入 TEXT_HTML 页面，可能造成反射型 XSS 或模板注入。

#### 根因

buildSearchPage直接字符串拼接query到HTML返回，未做任何编码，反射型XSS成立

#### 攻击路径

query 未经编码直接拼入 TEXT_HTML 页面，可能造成反射型 XSS 或模板注入。

#### 独立复核

漏洞假设（反射型 XSS）由源码直接证明：PageController.search 将客户端可控的 @RequestParam query 原样传给 pageService.buildSearchPage；PageService.buildSearchPage 将该 query 直接字符串拼接进 "<html>..." 响应体，未做任何 HTML 编码，控制器以 MediaType.TEXT_HTML_VALUE 返回。同文件的 buildSearchText 使用 HtmlUtils.htmlEscape(query)，对照表明 buildSearchPage 路径确实缺失输出编码，控制失效成立，反射型 XSS 假设得到支持。但候选中的"模板注入"部分未被证据支持：buildSearchPage 是普通字符串拼接，证据中不存在模板引擎调用，故仅 XSS 成立。

#### 修复建议

在GET /api/pages/search?query=到HTML 响应中的反射型 XSS / 模板注入之间实施并集中复用HTML 输出编码或模板自动转义，控制器未体现任何编码处理。

### 4. hardcoded_secret：ResourceSyncService通过@Value注入伙伴凭据

- 严重性：`medium`
- 置信度：`high`
- CWE：CWE-798
- 根因位置：`src/main/java/com/sinkspring/bench/service/ResourceSyncService.java:1`

#### 问题与影响

若配置文件含真实client-secret，则构成仓库内硬编码凭据暴露并可能外泄至第三方。

#### 根因

application.yml中client-secret为真实值（dh_live_Q7m4pN8xK2vL6sR9），ResourceSyncService通过@Value注入并在loadCatalog中放入X-Client-Secret头发往外部，构成URL硬编码凭据暴露。

#### 攻击路径

若配置文件含真实client-secret，则构成仓库内硬编码凭据暴露并可能外泄至第三方。

#### 独立复核

漏洞假设成立。证据直接证明：(1) 仓库内 src/main/resources/application.yml（属批准的配置读取范围）明文写入 partners.document-hub.client-secret: dh_live_Q7m4pN8xK2vL6sR9 及 client-id，构成仓库内硬编码凭据（CWE-798）；(2) ResourceSyncService 通过 @Value("${partners.document-hub.client-secret}") 注入该值，并在 loadCatalog() 中将其放入 X-Client-Secret 请求头发往外部主机（catalogLocations 中 https://example.com/... 的固定 URL）。"配置含真实client-secret"的条件由字面值满足，"凭据明文存入配置并经HTTP头发往外部"的控制失效与数据流均由两份证据的源码内容独立证明。

#### 修复建议

在ResourceSyncService通过@Value注入伙伴凭据到凭据明文存入配置并以HTTP头发往第三方之间实施并集中复用目标为固定HTTPS地址，但凭据值是否真实写入仓库配置未确认。。

### 5. unsafe_deserialization：POST /api/preferences/restore

- 严重性：`high`
- 置信度：`high`
- CWE：CWE-502
- 根因位置：`src/main/java/com/sinkspring/bench/controller/PreferenceController.java:1`

#### 问题与影响

restore 接口对客户端提供内容执行反序列化并回显类型，存在反序列化 RCE 高风险。

#### 根因

Controller.restore将外部content传入restoreSnapshot，Service使用无过滤ObjectInputStream.readObject，无ObjectInputFilter或校验。

#### 攻击路径

restore 接口对客户端提供内容执行反序列化并回显类型，存在反序列化 RCE 高风险。

#### 独立复核

漏洞假设（restore 接口对客户端提供内容执行无过滤反序列化并回显类型，构成反序列化 RCE 高风险）获得源码证据支持。根因：PreferenceService.restoreSnapshot 对入参 content 执行 Base64 解码后用 `new ObjectInputStream(new ByteArrayInputStream(payload)).readObject()` 直接反序列化，证据块中该方法及其类内均无 ObjectInputFilter、签名校验或类型白名单。可达性：PreferenceController 的 `@PostMapping("/restore")` 接收 `@RequestBody PreferenceRequest request`，将 `request.getContent()` 原样传入 restoreSnapshot，客户端可控内容直达 readObject sink；随后 `snapshot.getClass().getName()` 与 `snapshot.toString()` 回显反序列化结果类型与内容，与控制流描述一致。影响：对不可信字节流调用 ObjectInputStream.readObject() 是 CWE-502 经典不安全反序列化模式，一旦 classpath 存在可利用 gadget 即可导致 RCE，评级 high 合理（实际 RCE 执行取决于 classpath 中 gadget 类，本证据包无法证明具体利用链）。

#### 修复建议

在POST /api/preferences/restore到Java 对象反序列化（疑似 ObjectInputStream.readObject）之间实施并集中复用需 ObjectInputFilter/签名加密封装校验，控制器未体现任何过滤。

### 6. unsafe_deserialization：POST /api/preferences/desktop-import

- 严重性：`high`
- 置信度：`high`
- CWE：CWE-502
- 根因位置：`src/main/java/com/sinkspring/bench/controller/PreferenceController.java:1`

#### 问题与影响

desktop-import 解析客户端提供的桌面配置并返回任意 Object 类型，疑似自定义反序列化入口。

#### 根因

Controller.importDesktop将外部content传入importDesktopProfile，Service使用XMLDecoder.readObject()无任何类限制，可实例化任意Java对象。

#### 攻击路径

desktop-import 解析客户端提供的桌面配置并返回任意 Object 类型，疑似自定义反序列化入口。

#### 独立复核

证据支持漏洞假设。数据流完整且边界清晰：PreferenceController.importDesktop 通过 @RequestBody 接收客户端可控的 PreferenceRequest，将 content 原样传入 PreferenceService.importDesktopProfile；后者以 UTF-8 字节流构造 XMLDecoder 并直接调用 readObject()，无任何类白名单、格式校验或拒绝逻辑，返回任意 Object 类型并由控制器回显其类名与 toString。客户端输入从网络边界直达 XMLDecoder.readObject() 这一敏感反序列化操作，构成 CWE-502 不安全反序列化入口；任意 Java 对象可被实例化，风险成立。两条证据（控制器与服务源码）已足以证明根因、路径与影响类型，无需依赖推断。

#### 修复建议

在POST /api/preferences/desktop-import到桌面配置文件解析/反序列化（返回任意 Object 类型）之间实施并集中复用需格式校验与类白名单，控制器未体现任何校验。

### 7. unsafe_deserialization：PreferenceService.restoreSnapshot(String content)

- 严重性：`high`
- 置信度：`high`
- CWE：CWE-502
- 根因位置：`src/main/java/com/sinkspring/bench/controller/PreferenceController.java:1`

#### 问题与影响

攻击者提供恶意序列化流可在readObject触发gadget链导致RCE。

#### 根因

restoreSnapshot使用Base64解码后ObjectInputStream.readObject()，无任何过滤，Controller.restore端点直接可控。

#### 攻击路径

攻击者提供恶意序列化流可在readObject触发gadget链导致RCE。

#### 独立复核

漏洞假设得到证据支持。完整攻击路径可见：PreferenceController.restore（@PostMapping("/api/preferences/restore")，@RequestBody 接收 PreferenceRequest）调用 preferenceService.restoreSnapshot(request.getContent())；PreferenceService.restoreSnapshot 对攻击者可控的 String content 执行 Base64.getDecoder().decode 后，直接构造 ObjectInputStream(new ByteArrayInputStream(payload)) 并调用 readObject()，未设置 ObjectInputFilter、类白名单、黑名单或任何过滤，且解码/反序列化结果经 Controller 以 type/value 回显。攻击者可控的序列化字节可无过滤到达敏感操作 readObject，构成 CWE-502 不安全反序列化的控制失效；readObject 触发 gadget 链导致 RCE 是该无过滤反序列化 sink 的典型后果。结论仅覆盖所给两个源码文件中可独立证明的部分。

#### 修复建议

在PreferenceService.restoreSnapshot(String content)到ObjectInputStream.readObject()无过滤反序列化之间实施并集中复用未设置ObjectInputFilter或类白名单。。

### 8. unsafe_deserialization：PreferenceService.importDesktopProfile(String content)

- 严重性：`high`
- 置信度：`high`
- CWE：CWE-502
- 根因位置：`src/main/java/com/sinkspring/bench/controller/PreferenceController.java:1`

#### 问题与影响

XMLDecoder可解析object class构造恶意对象，是经典反序列化RCE入口。

#### 根因

importDesktopProfile使用XMLDecoder.readObject()解析外部XML，无类白名单或安全限制，Controller.desktop-import端点可达。

#### 攻击路径

XMLDecoder可解析object class构造恶意对象，是经典反序列化RCE入口。

#### 独立复核

根因成立：PreferenceService.java 中 importDesktopProfile(String content) 对 content.getBytes(StandardCharsets.UTF_8) 构造 ByteArrayInputStream 直接传入 XMLDecoder 并调用 decoder.readObject()，路径内无类白名单、输入校验或 XML 安全配置，符合 CWE-502 经典 XMLDecoder 反序列化入口。可达性成立：PreferenceController.java 中 @PostMapping("/desktop-import") 的 importDesktop 方法以 @RequestBody PreferenceRequest request 接收请求体，将 request.getContent() 传入 preferenceService.importDesktopProfile(...)，攻击者可控内容直达 readObject()，且解码对象的 class 名与 toString 被回显。影响合理：XMLDecoder 可通过 <object class="..."> 实例化任意 Java 对象并调用方法（如 ProcessBuilder.start()，仅需 JDK 自带类），构成命令执行，severity high 有依据。反证：所示源码路径中无任何防护（无校验、白名单、XML 安全配置、权限注解），未发现否定该假设的证据；用户提供的 security_context 与 threat_model 均为空，无覆盖前提。综合判定 supported。

#### 修复建议

在PreferenceService.importDesktopProfile(String content)到XMLDecoder.readObject()实例化任意Java对象之间实施并集中复用无任何类限制或XML安全配置。。

### 9. ssrf：GET /api/integrations/preview?location=...

- 严重性：`medium`
- 置信度：`high`
- CWE：CWE-918
- 根因位置：`src/main/java/com/sinkspring/bench/controller/IntegrationController.java:1`

#### 问题与影响

location可指向内网地址或任意文件，导致SSRF或路径穿越且结果回显

#### 根因

控制器将location直接传入loadPreview，方法内未校验scheme/主机即发起GET并回显响应体，控制失效成立。

#### 攻击路径

location可指向内网地址或任意文件，导致SSRF或路径穿越且结果回显

#### 独立复核

证据包内两个文件完整证明核心控制失效：IntegrationController.preview 将未校验的 @RequestParam location 直接传入 ResourceSyncService.loadPreview；loadPreview 以 URI.create(location) 构建 HttpRequest 发起 GET，并将响应体作为 "content" 原样返回调用方。所示代码路径中不存在任何 scheme/主机白名单或输入校验，攻击者提供的 http/https URL（可指向内网或回环地址，如 127.0.0.1、169.254.169.254）会被直接请求且响应回显，SSRF 控制失效（CWE-918）成立。但候选中的"任意文件/路径穿越"子主张不成立：sink 是 java.net.http.HttpClient，仅接受 http/https/ws/wss scheme，file:// URI 会在 HttpRequest.newBuilder 处抛 IllegalArgumentException 而非读取文件，且该方法未使用任何文件 I/O API。outcome 判定针对 SSRF 及响应回显这一核心假设（与 asset/ruleId 一致），路径穿越子主张不纳入支持范围。

#### 修复建议

在GET /api/integrations/preview?location=...到loadPreview中未授权的外部/内网请求并回显content之间实施并集中复用无任何白名单、协议或路径校验，参数直接透传服务层。

### 10. hardcoded_secret：未确认的HTTP端点（SessionService.verifySession的调用方）

- 严重性：`medium`
- 置信度：`high`
- CWE：CWE-798
- 根因位置：`src/main/java/com/sinkspring/bench/service/SessionService.java:1`

#### 问题与影响

攻击者已知硬编码密钥后可伪造任意subject或role的合法JWT通过verifySession

#### 根因

签名密钥硬编码于SessionService常量，application.yml无覆盖配置，/api/session/details使用verifySession校验，可伪造JWT通过。

#### 攻击路径

攻击者已知硬编码密钥后可伪造任意subject或role的合法JWT通过verifySession

#### 独立复核

漏洞假设得到源码证据支持。SessionService.java 将 SIGNING_KEY 硬编码为常量 "sinkspring-session-key"，verifySession 仅执行 JWT.require(Algorithm.HMAC256(SIGNING_KEY)).build().verify(token)，即只校验 HMAC 签名，不校验 audience/issuer，也未对 subject 或 role 声明做任何白名单/归属校验。SessionController.details（@GetMapping("/details")，映射于 /api/session 下，接收 Authorization 头）直接调用 verifySession 并把 token 中的 subject 与 role 声明原样返回。因此任何获知该硬编码密钥者可用同一 HMAC 密钥签发含任意 subject/role 的 JWT 并通过 verifySession，且控制器无额外校验会将其回显。application.yml 中不存在对该密钥的配置覆盖或外部密钥源，无法削弱硬编码事实。攻击前提（获知密钥）正是 CWE-798 所述硬编码密钥可被从源码/制品中提取的本质，源码本身已证明密钥为固定常量。

#### 修复建议

在未确认的HTTP端点（SessionService.verifySession的调用方）到Algorithm.HMAC256(SIGNING_KEY)的签名与验证之间实施并集中复用签名密钥硬编码于源码且强度不足，未从配置或密钥管理系统加载。

### 11. hardcoded_secret：登录端点（SessionService.openSession的调用方）

- 严重性：`medium`
- 置信度：`high`
- CWE：CWE-798
- 根因位置：`src/main/java/com/sinkspring/bench/service/SessionService.java:1`

#### 问题与影响

硬编码管理凭据可被源码泄露或暴力猜测利用，直接换取ADMIN令牌

#### 根因

登录接口直接调用openSession，硬编码凭据明文比对，配置无覆盖，成功即签发ADMIN令牌，攻击面可达。

#### 攻击路径

硬编码管理凭据可被源码泄露或暴力猜测利用，直接换取ADMIN令牌

#### 独立复核

漏洞假设成立（supported）。证据链完整：1) SessionService.java 硬编码 OPERATOR_USERNAME="ops-admin" 与 OPERATOR_PASSWORD="SpringOps#2026"，openSession 以明文 equals 比对 LoginRequest 中的凭据，无哈希、锁定或失败计数；2) SessionController 暴露 @PostMapping("/api/session/login")，直接调用 sessionService.openSession(request)，使攻击面可达（Spring MVC 公开端点，无鉴权注解）；3) 凭据匹配后 JWT.create().withClaim("role","ADMIN").withSubject("ACC-9001").sign(Algorithm.HMAC256(SIGNING_KEY)) 直接签发 ADMIN 令牌，SIGNING_KEY 亦为硬编码弱密钥；4) 已批准的 application.yml 中无这些凭据的外部化覆盖，也无速率限制/锁定配置。因此源码泄露即暴露精确凭据，暴力猜测亦无可见缓解，成功登录即换取 role=ADMIN 的 JWT，符合 CWE-798 硬编码凭据。用户上下文（security_context、supplied_threat_model 为空）与源码证据无冲突。

#### 修复建议

在登录端点（SessionService.openSession的调用方）到JWT.create().sign()签发管理员令牌之间实施并集中复用凭据明文硬编码，无密码哈希、失败锁定或审计日志。

### 12. expression_injection：POST /api/tools/calculate

- 严重性：`high`
- 置信度：`high`
- CWE：CWE-917
- 根因位置：`src/main/java/com/sinkspring/bench/controller/OperationsToolController.java:1`

#### 问题与影响

formula可注入表达式指令导致RCE或敏感信息读取

#### 根因

计算接口formula直接取自请求体，calculate用StandardEvaluationContext解析SpEL，攻击者可控表达式可达危险求值上下文

#### 攻击路径

formula可注入表达式指令导致RCE或敏感信息读取

#### 独立复核

漏洞假设supported。根因：OperationsToolService.calculate使用`StandardEvaluationContext context = new StandardEvaluationContext()`并将`formula`直接交给`parser.parseExpression(formula).getValue(context)`求值；与同一文件中calculatePreset使用`SimpleEvaluationContext.forReadOnlyDataBinding()`形成对照，证明calculate路径未采用受限上下文。可达性：OperationsToolController的`@PostMapping("/calculate")`把`@RequestBody ToolRequest request`的`request.getFormula()`原样传入`operationsToolService.calculate(request.getFormula(), request.getValues())`，formula完全攻击者可控，沿途无任何过滤/白名单/长度校验源码。影响：StandardEvaluationContext允许SpEL中的`T(...)`类型引用、任意方法调用与属性访问，可执行如`T(java.lang.Runtime).getRuntime().exec(...)`实现RCE，或读取类路径/系统属性/JVM可访问资源造成敏感信息泄露，因此“RCE或敏感信息读取”的影响判断成立。两条证据完整覆盖source→transformation→sink，根因、可达性、影响均有源码支持。

#### 修复建议

在POST /api/tools/calculate到calculate内表达式求值引擎之间实施并集中复用无输入长度或表达式白名单证据。

### 13. expression_injection：未确认的HTTP端点（OperationsToolService.calculate的调用方）

- 严重性：`high`
- 置信度：`high`
- CWE：CWE-917
- 根因位置：`src/main/java/com/sinkspring/bench/service/OperationsToolService.java:1`

#### 问题与影响

若formula源自请求参数，SpEL表达式注入可导致任意代码执行（RCE）

#### 根因

controller证实formula来自HTTP请求体，calculate以StandardEvaluationContext执行parseExpression(formula).getValue(context)，构成SpEL注入RCE

#### 攻击路径

若formula源自请求参数，SpEL表达式注入可导致任意代码执行（RCE）

#### 独立复核

漏洞假设成立。控制器证据证实存在确定的HTTP入口：OperationsToolController.calculate（POST /api/tools/calculate，@RequestBody ToolRequest）直接调用 operationsToolService.calculate(request.getFormula(), request.getValues())，formula源自请求体。服务端 calculate 使用 StandardEvaluationContext（允许反射式任意类/方法调用，无类型或方法白名单），并将来自请求的 formula 直接传入 parser.parseExpression(formula).getValue(context)，无任何校验或过滤。request.getFormula() 与 getValue 之间的数据流在源码中连续且无中间处理，满足“formula源自请求参数”的前提，构成SpEL表达式注入，利用StandardEvaluationContext可导致任意代码执行（RCE）。（注：candidate标题称端点“未确认”，但控制器证据已确认该HTTP端点存在，此标签与证据不符，不影响结论。）

#### 修复建议

在未确认的HTTP端点（OperationsToolService.calculate的调用方）到expression.getValue(context)（SpEL表达式求值）之间实施并集中复用calculate使用StandardEvaluationContext且无类型或方法白名单，任意类方法可被调用。

### 14. template_injection：POST /api/tools/messages/preview

- 严重性：`high`
- 置信度：`high`
- CWE：CWE-1336
- 根因位置：`src/main/java/com/sinkspring/bench/controller/OperationsToolController.java:1`

#### 问题与影响

template可注入模板指令导致SSTI

#### 根因

controller中/messages/preview将用户可控template直接传入renderMessage，service使用FreeMarker且显式设置UNRESTRICTED_RESOLVER，无沙箱，可SSTI。

#### 攻击路径

template可注入模板指令导致SSTI

#### 独立复核

证据链完整支持SSTI假设。OperationsToolController.previewMessage（POST /api/tools/messages/preview）将 @RequestBody ToolRequest.getTemplate() 原样传入 operationsToolService.renderMessage(request.getTemplate(), request.getValues())，渲染结果放入 Map.of("content", ...) 随HTTP响应回显。OperationsToolService.renderMessage 使用 FreeMarker 2.3.32 Configuration（StringTemplateLoader），显式设置 TemplateClassResolver.UNRESTRICTED_RESOLVER，以用户提供的 template 字符串为模板源码执行 template.process(values, output)，全程无沙箱、无模板白名单、无输入校验。FreeMarker 模板本身可包含任意指令（如 ?new 实例化任意类），在 UNRESTRICTED_RESOLVER 下类解析不受限，攻击者可控 template 即构成模板注入/SSTI，并可升级为任意类实例化乃至RCE。输入→控制器→服务→模板引擎渲染→响应回显的路径均由所给源码直接可见。

#### 修复建议

在POST /api/tools/messages/preview到renderMessage内模板引擎渲染并回显content之间实施并集中复用无模板白名单或沙箱证据。

### 15. template_injection：未确认的HTTP端点（OperationsToolService.renderMessage的调用方）

- 严重性：`high`
- 置信度：`high`
- CWE：CWE-1336
- 根因位置：`src/main/java/com/sinkspring/bench/controller/OperationsToolController.java:1`

#### 问题与影响

若模板源或变量值可控，可借助放开类解析调用任意类方法实现SSTI

#### 根因

现有证据显示renderMessage的唯一调用方为/messages/preview，source源自请求体template，FreeMarker配置UNRESTRICTED_RESOLVER，模板注入可利用。

#### 攻击路径

若模板源或变量值可控，可借助放开类解析调用任意类方法实现SSTI

#### 独立复核

证据支持SSTI漏洞假设。controller证据（file:ce831718…）显示@PostMapping("/api/tools/messages/preview")接收@RequestBody ToolRequest，直接调用operationsToolService.renderMessage(request.getTemplate(), request.getValues())，未见任何校验/转义/白名单，HTTP请求体template成为模板源。service证据（file:fb5025bd…）显示构造器设置Configuration(VERSION_2_3_32)并执行setNewBuiltinClassResolver(TemplateClassResolver.UNRESTRICTED_RESOLVER)——即显式解除类解析限制（漏洞使能项），renderMessage中new Template("message", source, templateConfiguration)后template.process(values, output)渲染攻击者可控模板。根因成立：放开类解析+可控模板源；可达性成立：POST端点请求体直达sink，无中间防护证据；影响成立：模板可经?new()等内建函数实例化任意类（如freemarker.template.utility.*）并调用方法，具备RCE潜力，评级high合理。证据包内无反证：无校验、无沙箱、无受限resolver。未动态复现；候选remediation文字反建议启用UNRESTRICTED_RESOLVER（与修复方向相反），但不影响漏洞假设成立。

#### 修复建议

在未确认的HTTP端点（OperationsToolService.renderMessage的调用方）到template.process(values, output)（FreeMarker服务端模板注入）之间实施并集中复用构造器执行setNewBuiltinClassResolver(TemplateClassResolver.UNRESTRICTED_RESOLVER)显式放开类解析限制。

### 16. hardcoded_secret：src/main/resources/application.yml partners.document-hub段

- 严重性：`medium`
- 置信度：`high`
- CWE：CWE-798
- 根因位置：`src/main/resources/application.yml:1`

#### 问题与影响

生产环境client-secret明文提交且可能随出站请求暴露，泄露即接管合作伙伴身份。

#### 根因

application.yml明文存储client-secret，ResourceSyncService通过@Value注入并放入X-Client-Secret头发往出站HTTP调用，链路完整。

#### 攻击路径

生产环境client-secret明文提交且可能随出站请求暴露，泄露即接管合作伙伴身份。

#### 独立复核

核心漏洞假设（client-secret 明文提交且随出站鉴权请求暴露）由两份证据直接证明：(1) application.yml 的 partners.document-hub.client-secret 以明文 dh_live_Q7m4pN8xK2vL6sR9 写入配置，无任何加密或外部化指示；(2) ResourceSyncService 通过 @Value 注入该属性，并在 loadCatalog() 的出站 GET 请求中将其作为 X-Client-Secret 头发往外部 catalog 端点（与 client-id 一并发送）。两者构成完整链：明文配置→注入→出站鉴权头，符合 CWE-798 硬编码凭据的根因与路径。未发现反证：证据中不存在 vault/环境变量间接引用或加密处理。影响评级为 medium 合理（外部 document-hub 凭据泄露），但"生产环境"部署状态与"接管合作伙伴身份"的具体影响属于仓库外外部系统后果，无法由源码独立证实，已在 limitations 中说明。

#### 修复建议

在src/main/resources/application.yml partners.document-hub段到外部document-hub API的鉴权请求之间实施并集中复用已批准配置中secret无任何加密或外部化处理。

### 17. session_flaw：POST /api/session/login（JSON body为LoginRequest）

- 严重性：`medium`
- 置信度：`high`
- CWE：未分类
- 根因位置：`src/main/java/com/sinkspring/bench/controller/SessionController.java:1`

#### 问题与影响

openSession可能弱校验凭据或以弱/硬编码密钥签发会话token

#### 根因

openSession硬编码固定用户名密码和HMAC签名密钥，凭据与密钥来源均无外部配置，弱校验与弱密钥由源码完整证明。

#### 攻击路径

openSession可能弱校验凭据或以弱/硬编码密钥签发会话token

#### 独立复核

漏洞假设被源码证据直接支持。SessionService.openSession 以私有静态常量硬编码唯一凭据（OPERATOR_USERNAME="ops-admin"、OPERATOR_PASSWORD="SpringOps#2026"）并通过严格相等校验，凭据无任何外部配置来源（application.yml 中亦无相关配置键）；JWT 使用硬编码低熵密钥 SIGNING_KEY="sinkspring-session-key" 经 Algorithm.HMAC256 签名（subject=ACC-9001, role=ADMIN, 8小时过期）。SessionController.login 将 openSession 返回的 token 经 Map.of("token",...) 直接写入 HTTP 响应。因此"弱/硬编码凭据校验"与"以弱/硬编码密钥签发会话token"两个构成要素均由证据中的源码直接证明，攻击路径从 POST /api/session/login（LoginRequest JSON）到响应 token 完整可循。

#### 修复建议

在POST /api/session/login（JSON body为LoginRequest）到HTTP响应中的会话token之间实施并集中复用未知，需验证openSession的凭据校验强度、JWT签名密钥与过期策略。

### 18. object_level_authorization：GET /api/accounts/{accountId}

- 严重性：`medium`
- 置信度：`high`
- CWE：CWE-639
- 根因位置：`src/main/java/com/sinkspring/bench/controller/AccountController.java:1`

#### 问题与影响

若getAccount未比较requesterId与accountId的归属，则可水平越权读取任意账户。

#### 根因

AccountService.getAccount直接调用findById(accountId)，忽略requesterId，且DAO查询无owner条件，横向越权完全成立。

#### 攻击路径

若getAccount未比较requesterId与accountId的归属，则可水平越权读取任意账户。

#### 独立复核

证据支持该IDOR（CWE-639）漏洞假设。调用链完整：AccountController的GET /{accountId}端点将请求头X-Account-Id（requesterId）与路径参数accountId一并传入AccountService.getAccount；该服务方法完全忽略requesterId，直接调用accountRepository.findById(accountId)；DAO查询仅以account_id为条件（无owner/requester归属过滤），并返回display_name、email、role、notes等账户数据。因此任何能访问该端点的调用者，只要替换路径中的accountId即可读取任意账户，getAccount在提供的代码路径中确实未进行requesterId与accountId的归属比较，水平越权读取成立。

#### 修复建议

在GET /api/accounts/{accountId}到AccountService.getAccount返回账户数据之间实施并集中复用无可见归属校验。

### 19. arbitrary_file_write：POST /api/documents/content

- 严重性：`high`
- 置信度：`high`
- CWE：CWE-73
- 根因位置：`src/main/java/com/sinkspring/bench/controller/DocumentController.java:1`

#### 问题与影响

请求中的文件名与内容被直接写入文件系统，可导致任意文件写入。

#### 根因

Controller将无注解校验的DocumentRequest直接传入storeDocument，服务端以documentRoot.resolve(path)构造路径并无normalize/越界检查，CREATE+TRUNCATE_EXISTING写入，攻击者可控path/content可实现任意文件写入。

#### 攻击路径

请求中的文件名与内容被直接写入文件系统，可导致任意文件写入。

#### 独立复核

证据链在提供的三个文件中完整成立：DocumentController.putContent() 将无校验注解的 @RequestBody DocumentRequest 直接传给 documentService.storeDocument(request)（controller 与 DTO 证据）。DocumentService.storeDocument 用 documentRoot.resolve(request.getPath()) 构造写入路径：resolve() 不归一化且对绝对路径直接返回绝对路径，代码未做 normalize()/startsWith(root) 越界检查（与同文件 loadPublishedDocument 的防护形成对比，后者仅保护读路径）；随后对 getParent() 执行 createDirectories 并以 Files.writeString(CREATE+TRUNCATE_EXISTING) 将 request.getContent() 原样写入。攻击者可控的 path 与 content 从 HTTP 请求体直达文件系统写入操作，控制失效（无路径边界校验）成立，可造成路径穿越式任意文件写入，影响限于运行进程的 OS 写权限。问题假设得到源码证明。

#### 修复建议

在POST /api/documents/content到服务端文件写入之间实施并集中复用无可见上传类型与路径校验。

### 20. arbitrary_file_write：DocumentService.storeDocument(DocumentRequest)

- 严重性：`high`
- 置信度：`high`
- CWE：CWE-73
- 根因位置：`src/main/java/com/sinkspring/bench/service/DocumentService.java:1`

#### 问题与影响

若path与content均受请求控制，可实现任意相对路径文件写入甚至覆盖敏感文件

#### 根因

DocumentService.storeDocument以documentRoot.resolve(request.getPath())构造路径，执行Files.createDirectories(parent)与Files.writeString(CREATE,TRUNCATE_EXISTING)，无normalize/startsWith校验，path与content均来自无校验的DocumentRequest，可路径穿越写出root并覆盖文件。

#### 攻击路径

若path与content均受请求控制，可实现任意相对路径文件写入甚至覆盖敏感文件

#### 独立复核

漏洞假设由源码证据证明。DocumentService.storeDocument 直接以 documentRoot.resolve(request.getPath()) 构造目标路径，未做 normalize/startsWith 越界校验，且对 parent 自动 createDirectories；DocumentRequest 仅为无任何校验注解的 path/content DTO；DocumentController 的 POST /api/documents/content 以 @RequestBody 接收请求并直接调用 storeDocument。Files.writeString 以 CREATE/TRUNCATE_EXISTING 写入，故 path 含 "../" 或为绝对路径时可写出 documentRoot 并新建/截断覆盖进程可写文件，content 完全受请求控制。输入到敏感写操作的完整路径（控制器→服务→sink）均由证据中的三个文件直接支撑。

#### 修复建议

在DocumentService.storeDocument(DocumentRequest)到Files.writeString(Path,content,UTF_8)之间实施并集中复用无路径校验与内容白名单，路径穿越可写出documentRoot。

### 21. jndi_injection：GET /api/tools/directory?name=...

- 严重性：`high`
- 置信度：`high`
- CWE：CWE-74
- 根因位置：`src/main/java/com/sinkspring/bench/controller/OperationsToolController.java:1`

#### 问题与影响

name进入JNDI查找，可指向远程LDAP/RMI触发JNDI注入

#### 根因

控制器将外部name参数直接传入lookupDirectory，该方法无任何过滤便执行InitialContext.lookup，构成完整JNDI注入链。

#### 攻击路径

name进入JNDI查找，可指向远程LDAP/RMI触发JNDI注入

#### 独立复核

证据包内源码完整证明了该漏洞假设的控制流与数据流：OperationsToolController.directoryEntry 将外部可控的 @RequestParam String name（GET /api/tools/directory）原样传入 operationsToolService.lookupDirectory(name)，服务方法未做任何过滤、校验或协议/地址白名单，直接执行 new InitialContext().lookup(name)，并将结果以 String.valueOf 返回。输入经边界（HTTP查询参数）跨越到敏感操作（JNDI/LDAP/RMI 名称查找），异常类型 NamingException 亦佐证该查找为 JNDI 操作。InitialContext.lookup 接受任意 JNDI 名称（含 ldap://、rmi:// 形式的远程地址），因此"name可指向远程LDAP/RMI触发JNDI注入"这一注入链路由源码直接证明，候选的根因、攻击路径和可达性描述与证据一致。控制失效成立：源码中不存在任何缓解该 sink 的代码级控制。

#### 修复建议

在GET /api/tools/directory?name=...到lookupDirectory内JNDI查找之间实施并集中复用无协议或地址限制证据。

### 22. jndi_injection：未确认的调用方（OperationsToolService.lookupDirectory）

- 严重性：`high`
- 置信度：`high`
- CWE：CWE-74
- 根因位置：`src/main/java/com/sinkspring/bench/controller/OperationsToolController.java:1`

#### 问题与影响

若name由攻击者控制，可指向恶意RMI或LDAP端点触发反序列化或RCE

#### 根因

现有控制器证据确认lookupDirectory有外部GET入口，且方法内直接对可控name执行JNDI lookup，利用链可达。

#### 攻击路径

若name由攻击者控制，可指向恶意RMI或LDAP端点触发反序列化或RCE

#### 独立复核

待审漏洞假设：攻击者可控的name传入InitialContext().lookup(name)可构成JNDI注入。证据链完整：OperationsToolController的GET /api/tools/directory入口以@RequestParam String name接收攻击者可控输入，未经任何校验直接调用operationsToolService.lookupDirectory(name)；OperationsToolService.lookupDirectory内new InitialContext().lookup(name)直接以该字符串执行JNDI解析，无协议白名单或名称限制，结果经String.valueOf返回。外部入口（控制器）、调用方（控制器→服务）、敏感操作（JNDI lookup）及输入到sink的直接数据流均由所给源码证明。无任何过滤、验证或防护控件可见。JNDI注入根因成立，攻击者可将name指向恶意RMI/LDAP端点；具体是否升级为RCE取决于运行时JDK版本及系统属性（如trustURLCodebase、com.sun.jndi.rmi.object.trustURLCodebase等），该前提未在证据中确认，属影响程度限制而非根因否定。故漏洞假设（JNDI注入/不安全JNDI名称解析）supported。

#### 修复建议

在未确认的调用方（OperationsToolService.lookupDirectory）到InitialContext().lookup(name)（JNDI注入）之间实施并集中复用lookupDirectory未对JNDI名称做白名单或协议限制。

## 待独立复核候选

### unknown：GET /api/navigation/section?name=...

该入口受固定映射约束，输出不可控，无可信攻击路径

- 调查编号：`investigation-3`
- 建议严重性：`medium`

### xss：GET /api/pages/{pageId}

renderPage 渲染用户可控页面内容并以 TEXT_HTML 返回，存在存储型 XSS 或模板注入风险。

- 调查编号：`investigation-5`
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

