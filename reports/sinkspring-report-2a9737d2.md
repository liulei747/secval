# Secval 安全审计报告

- 任务 ID：`2a9737d241294a7f8dba00a44633a7b8`
- 状态：`needs_review`
- 报告收口：`partial_report`

## 执行摘要

本次审计经独立静态复核确认 23 条正式安全发现，最高严重性为 high。xxe：POST /api/catalog/import (XML)；open_redirect：GET /api/navigation/continue?next=...；xss：GET /api/pages/search?query=；xss：GET /api/pages/{pageId}；hardcoded_secret：ResourceSyncService通过@Value注入伙伴凭据；另有 18 条。每条发现均在下文列出根因位置、攻击路径、复核结论和修复建议；未覆盖范围与静态分析限制见“覆盖与限制”。

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

漏洞假设成立。源码证据完整证明不安全解析配置与可达数据流：(1) CatalogController 的 POST /api/catalog/import（consumes=APPLICATION_XML）将请求体 String content 直接传给 catalogImportService.importCatalog(content)；(2) importCatalog 中 DocumentBuilderFactory 显式 setFeature("disallow-doctype-decl", false)、开启 external-general-entities 与 external-parameter-entities、setExpandEntityReferences(true)，且未设置 ACCESS_EXTERNAL_DTD/SCHEMA 限制，即解析器明确启用 DTD 与外部实体处理，满足假设前提"未禁用DTD与外部实体"；(3) 解析结果 getTextContent() 经控制器以 "content" 键返回响应，XXE 读取的文件内容可回显（文件读取影响明确；SSRF 取决于 JDK 默认 accessExternalDTD 是否允许 http）。同一文件中的 summarizeCatalog（/summary 端点）采用安全配置，与 /import 路径无关，不构成对该路径的反证。

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

证据直接证明控制失效。NavigationController.continueTo() 中 @RequestParam String next 接收攻击者可控查询参数，未经任何校验/白名单/清洗即经 URI.create(next) 放入 ResponseEntity.status(302).location(...) 的 Location 头并返回。URI.create 对绝对外部 URL（如 https://evil.com）有效，浏览器将跟随该 302 重定向，形成开放重定向（CWE-601）。同一类中 section 端点使用固定 destinations 白名单，对比说明 /continue 缺失校验并非设计忽略项；next 参数的数据流（来源→URI.create→302 Location）完全在该文件中闭环，无局部防护。

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

源码证据支持反射型 XSS 假设。PageController.search 暴露 GET /api/pages/search 且 produces=TEXT_HTML，将客户端可控的 @RequestParam query 原样传给 PageService.buildSearchPage；buildSearchPage 通过字符串拼接把 query 嵌入 HTML（"<html>...Results for " + query + ...）且无任何编码。同文件中 buildSearchText 对 query 使用 HtmlUtils.htmlEscape，对比可证该 HTML 路径确实缺少输出编码。@RestController 返回 String 由 StringHttpMessageConverter 直接写回响应体，无模板引擎自动转义，故含 HTML 元字符的 query 将被原样反射，反射型 XSS（CWE-79）成立。模板注入主张未被证明：该路径仅做纯字符串拼接，未见任何模板引擎参与。

#### 修复建议

在GET /api/pages/search?query=到HTML 响应中的反射型 XSS / 模板注入之间实施并集中复用HTML 输出编码或模板自动转义，控制器未体现任何编码处理。

### 4. xss：GET /api/pages/{pageId}

- 严重性：`medium`
- 置信度：`high`
- CWE：CWE-79
- 根因位置：`src/main/java/com/sinkspring/bench/controller/PageController.java:1`

#### 问题与影响

renderPage 渲染用户可控页面内容并以 TEXT_HTML 返回，存在存储型 XSS 或模板注入风险。

#### 根因

renderPage拼接page中TITLE与BODY到HTML返回，无输出编码，存储型XSS成立

#### 攻击路径

renderPage 渲染用户可控页面内容并以 TEXT_HTML 返回，存在存储型 XSS 或模板注入风险。

#### 独立复核

证据支持存储型 XSS 假设。完整链路在提供的源码内自洽：POST /api/pages 将用户可控的 title/body（PageRequest DTO）经 PageRepository.save 以参数化 MERGE 语句持久化；GET /api/pages/{pageId}（produces=TEXT_HTML）经 PageService.renderPage 将 page 映射中的 "TITLE" 与 "BODY" 直接字符串拼接进 HTML 返回，无任何输出编码（对比同文件 buildSearchText 使用了 HtmlUtils.htmlEscape，而 renderPage 未使用）。因此攻击者存储的恶意 HTML/脚本会未经转义地以 text/html 返回给查看该页面的用户，构成存储型 XSS。pageId 仅作参数化查询键，不参与渲染输出，且 SQL 注入已被占位符防护。注意：证据仅支持 XSS，不支持"模板注入"表述——renderPage 是纯字符串拼接，未调用任何模板引擎。

#### 修复建议

在GET /api/pages/{pageId}到HTML 响应中的存储型 XSS / 模板注入之间实施并集中复用存储内容输出编码与 pageId 路径校验，控制器未体现防护。

### 5. hardcoded_secret：ResourceSyncService通过@Value注入伙伴凭据

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

证据证实：application.yml（仓库内 src/main/resources）明文包含 client-secret 值 dh_live_Q7m4pN8xK2vL6sR9；ResourceSyncService 通过 @Value("${partners.document-hub.client-secret}") 注入该值，并在 loadCatalog() 中将其放入 X-Client-Secret 请求头发往外部固定 URL。这支持"仓库内硬编码凭据暴露"（CWE-798）的漏洞假设。但"真实有效凭据"与"外泄至第三方"两项前提仅部分成立：凭据有效性无法从源码确认（dh_live_ 前缀仅表明格式）；凭据仅发往固定伙伴地址，未发现发往攻击者可控目的地的路径。

#### 修复建议

在ResourceSyncService通过@Value注入伙伴凭据到凭据明文存入配置并以HTTP头发往第三方之间实施并集中复用目标为固定HTTPS地址，但凭据值是否真实写入仓库配置未确认。。

### 6. unsafe_deserialization：POST /api/preferences/restore

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

证据直接证明漏洞假设成立：PreferenceController.restore 以 @RequestBody 接收客户端 PreferenceRequest 并取 content 传给 PreferenceService.restoreSnapshot；restoreSnapshot 将 content Base64 解码后直接 new ObjectInputStream(new ByteArrayInputStream(payload)) 并调用 readObject()，方法声明抛 ClassNotFoundException，代码中无 ObjectInputFilter、无白名单/黑名单、无签名或封装校验；反序列化返回的 Object 的类名与 toString 被回显到响应。客户端可控内容跨信任边界直达 readObject 敏感操作，构成无过滤 Java 反序列化 sink（CWE-502）。"RCE 高风险"作为该 sink 的典型后果成立；实际利用依赖 classpath gadget，未在证据中证明，作为限制记录而不否定漏洞假设。

#### 修复建议

在POST /api/preferences/restore到Java 对象反序列化（疑似 ObjectInputStream.readObject）之间实施并集中复用需 ObjectInputFilter/签名加密封装校验，控制器未体现任何过滤。

### 7. unsafe_deserialization：POST /api/preferences/desktop-import

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

证据支持该漏洞假设（unsafe_deserialization / CWE-502 不安全反序列化入口）。源码链完整且直接：PreferenceController.importDesktop 通过 @RequestBody PreferenceRequest 接收客户端可控的 content，未做任何校验即调用 PreferenceService.importDesktopProfile；该 service 方法将 content 以 UTF-8 字节流喂给 XMLDecoder 并调用 readObject()，无类白名单、格式校验或任何过滤，随后控制器将返回的任意 Object 的类名与 toString 回显给客户端。这构成从客户端输入到不安全反序列化原语的已证实数据流，满足"解析客户端提供的桌面配置并返回任意 Object 类型"的漏洞假设。

#### 修复建议

在POST /api/preferences/desktop-import到桌面配置文件解析/反序列化（返回任意 Object 类型）之间实施并集中复用需格式校验与类白名单，控制器未体现任何校验。

### 8. unsafe_deserialization：PreferenceService.restoreSnapshot(String content)

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

证据支持漏洞假设。源码显示完整数据路径：PreferenceController.restore 端点（@PostMapping("/api/preferences/restore")，@RequestBody PreferenceRequest）将请求体 content 传入 PreferenceService.restoreSnapshot(String content)，该方法对 content 做 Base64 解码后 new ObjectInputStream(new ByteArrayInputStream(payload)) 并直接调用 readObject()，未设置 ObjectInputFilter、类白名单或任何过滤。攻击者可控输入未经有效控制即到达敏感反序列化 sink，构成 CWE-502 无过滤反序列化；readObject 成功返回后结果类型/值还被回显到响应（type/value）。证据中未发现任何有效防护（无 filter、无白名单、无长度/类型校验、端点无认证注解）。

#### 修复建议

在PreferenceService.restoreSnapshot(String content)到ObjectInputStream.readObject()无过滤反序列化之间实施并集中复用未设置ObjectInputFilter或类白名单。。

### 9. unsafe_deserialization：PreferenceService.importDesktopProfile(String content)

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

证据支持该漏洞假设。链路完整可核：PreferenceController 的 POST /api/preferences/desktop-import 端点以 @RequestBody 接收 PreferenceRequest（含无校验的 content 字段），将其 content 原样传入 preferenceService.importDesktopProfile(request.getContent())；PreferenceService.importDesktopProfile 对 content 直接执行 content.getBytes(UTF_8) → new ByteArrayInputStream → new XMLDecoder(...) → decoder.readObject()。两个源码片段中均无类白名单、输入校验或任何 XML 安全配置（如禁用外部实体、限制实例化类）。XMLDecoder.readObject() 可经 <object class="..."> 标签实例化任意 Java 类并调用构造器/方法（如 java.lang.ProcessBuilder），属经典不安全反序列化 RCE 入口（CWE-502），且 JDK 自带类即足以构成利用链。攻击者可控输入与敏感反序列化操作之间边界跨越清晰，控制未失效的防护证据不存在。

#### 修复建议

在PreferenceService.importDesktopProfile(String content)到XMLDecoder.readObject()实例化任意Java对象之间实施并集中复用无任何类限制或XML安全配置。。

### 10. ssrf：GET /api/integrations/preview?location=...

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

源码证据支持SSRF漏洞假设（CWE-918）。IntegrationController.preview将未校验的@RequestParam location直接传入ResourceSyncService.loadPreview；loadPreview对URI.create(location)发起HttpClient GET请求，无scheme/主机/内网地址校验，并将response.body()经Map.of("content",...)回显给调用方。控制失效、数据流与结果回显均被证据文件直接证明。但“任意文件/路径穿越”子主张被源码反证：sink是java.net.http.HttpClient的HTTP(S)请求，HttpRequest.newBuilder仅接受http/https URI，file://等scheme会抛异常，不存在文件读取路径。“未授权/无需认证”可达性前提未被证据包证明（无安全配置证据），仅影响严重性评估，不影响SSRF控制失效本身成立。

#### 修复建议

在GET /api/integrations/preview?location=...到loadPreview中未授权的外部/内网请求并回显content之间实施并集中复用无任何白名单、协议或路径校验，参数直接透传服务层。

### 11. hardcoded_secret：未确认的HTTP端点（SessionService.verifySession的调用方）

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

核心漏洞假设由源码直接证明：SessionService 将签名密钥硬编码为常量 SIGNING_KEY="sinkspring-session-key"（证据1），openSession 用该密钥 HMAC256 签发、verifySession 用同一密钥验签，JWT.require(...).build().verify(token) 仅校验签名与过期时间，不校验 issuer/audience；application.yml（证据2）不含任何会话密钥覆盖配置。SessionController（证据3）将 GET /api/session/details 映射到 verifySession，接收 Authorization 头并回显 subject/role。因此在"攻击者已知该硬编码密钥"的前提成立时，攻击者可自签含任意 subject/role 且未过期的 JWT 通过 verifySession，控制失效（CWE-798 硬编码密钥致认证可伪造）成立，评级 medium 与证据相符。

#### 修复建议

在未确认的HTTP端点（SessionService.verifySession的调用方）到Algorithm.HMAC256(SIGNING_KEY)的签名与验证之间实施并集中复用签名密钥硬编码于源码且强度不足，未从配置或密钥管理系统加载。

### 12. hardcoded_secret：登录端点（SessionService.openSession的调用方）

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

源码证据支持漏洞假设。SessionService.java 硬编码 OPERATOR_USERNAME="ops-admin"、OPERATOR_PASSWORD="SpringOps#2026"，openSession 将 LoginRequest 与这些常量明文比对，匹配即 JWT.create().withSubject("ACC-9001").withClaim("role","ADMIN").sign(Algorithm.HMAC256(SIGNING_KEY)) 签发 ADMIN 令牌。SessionController 的 POST /api/session/login 无前置认证，直接以 @RequestBody 将攻击者可控输入传入 openSession，登录端点（调用方）到 JWT 签发 sink 的路径完整可达。application.yml（唯一批准可读配置）未覆盖上述凭据。证据包内未见哈希存储、失败锁定或审计日志等有效防护。因此“硬编码管理凭据经源码泄露获取后可直接换取 ADMIN 令牌”的控制失效假设成立。

#### 修复建议

在登录端点（SessionService.openSession的调用方）到JWT.create().sign()签发管理员令牌之间实施并集中复用凭据明文硬编码，无密码哈希、失败锁定或审计日志。

### 13. expression_injection：POST /api/tools/calculate

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

漏洞假设成立（supported）。源码证据链完整：OperationsToolController 的 POST /api/tools/calculate 将请求体 ToolRequest 中的 formula 字段直接传入 operationsToolService.calculate(formula, values)；OperationsToolService.calculate 用 SpelExpressionParser 对 formula 执行 parseExpression(...).getValue(new StandardEvaluationContext())，无白名单、无长度限制、未使用受限的 SimpleEvaluationContext。StandardEvaluationContext 允许类型引用（T(...)）与任意方法调用，攻击者可控表达式可调用 java.lang.ProcessBuilder/Runtime 等实现 RCE，或经 T(java.lang.System).getenv()/文件读取等实现敏感信息读取。输入（RequestBody formula）到敏感操作（SpEL 求值引擎）路径被源码直接证明，未发现任何有效防护。

#### 修复建议

在POST /api/tools/calculate到calculate内表达式求值引擎之间实施并集中复用无输入长度或表达式白名单证据。

### 14. expression_injection：未确认的HTTP端点（OperationsToolService.calculate的调用方）

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

漏洞假设成立。控制器OperationsToolController的POST /api/tools/calculate用@RequestBody ToolRequest绑定请求体，ToolRequest含String formula字段，request.getFormula()被直接传给operationsToolService.calculate(formula, values)，无任何校验或过滤。calculate方法以SpelExpressionParser.parseExpression(formula)解析并调用getValue(context)，上下文为StandardEvaluationContext且未设置类型/方法白名单（区别于calculatePreset使用的SimpleEvaluationContext只读数据绑定上下文，但calculatePreset不处理攻击者公式）。StandardEvaluationContext允许T(...)类型引用与任意方法反射调用，是标准SpEL RCE前提（CWE-917）。源码证据链完整：HTTP请求体formula → calculate(formula, values) → parseExpression → getValue(StandardEvaluationContext)。candidate_detail中"未确认的HTTP端点"已被控制器证据补全确认。

#### 修复建议

在未确认的HTTP端点（OperationsToolService.calculate的调用方）到expression.getValue(context)（SpEL表达式求值）之间实施并集中复用calculate使用StandardEvaluationContext且无类型或方法白名单，任意类方法可被调用。

### 15. template_injection：POST /api/tools/messages/preview

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

证据支持SSTI漏洞假设。路径闭环成立：OperationsToolController.previewMessage接收RequestBody中的ToolRequest.template，直接调用operationsToolService.renderMessage(template, values)；OperationsToolService.renderMessage将未过滤的source作为FreeMarker模板源（new Template("message", source, templateConfiguration)）并用values数据模型执行process，渲染结果作为"content"回显到HTTP响应。Service构造函数显式设置templateConfiguration.setNewBuiltinClassResolver(TemplateClassResolver.UNRESTRICTED_RESOLVER)，即明确禁用FreeMarker默认的类解析限制，无沙箱、无模板白名单、无输入校验；攻击者注入<#assign x="freemarker.template.utility.Execute"?new()>${x(...)} 一类指令可被求值（可导致任意类实例化/命令执行），注入的${...}、<#...>指令亦会被求值并回显。工具链中所有其他提供文件（MyBatisConfig、WebConfig、Repository、DTO）不含影响该路径的模板沙箱、白名单或校验。candidate_detail的根因、数据流、可达性、影响均与源码证据一致。

#### 修复建议

在POST /api/tools/messages/preview到renderMessage内模板引擎渲染并回显content之间实施并集中复用无模板白名单或沙箱证据。

### 16. template_injection：未确认的HTTP端点（OperationsToolService.renderMessage的调用方）

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

证据链完整支持SSTI漏洞假设，且候选所称"未确认的HTTP端点"实际已被证据确认。OperationsToolController.previewMessage标注@PostMapping("/messages/preview")，以@RequestBody接收ToolRequest，直接调用operationsToolService.renderMessage(request.getTemplate(), request.getValues())；ToolRequest的template(String)与values(Map)字段均来自请求体，模板源完全攻击者可控，条件性前提"模板源或变量值可控"已被源码证明成立而非仅假设。OperationsToolService构造器显式执行setNewBuiltinClassResolver(TemplateClassResolver.UNRESTRICTED_RESOLVER)，renderMessage以用户提供的source字符串和该配置构建Template并执行template.process(values, output)，全程无过滤、无沙箱、values未净化。UNRESTRICTED_RESOLVER使模板可通过?new内建实例化任意类（如freemarker.template.utility.Execute）并调用方法，构成经典FreeMarker服务端模板注入（CWE-1336），可提升为任意代码执行。候选对根因、可达路径（HTTP端点→renderMessage→Template.process）与高影响评级均有对应源码证据，判定supported。

#### 修复建议

在未确认的HTTP端点（OperationsToolService.renderMessage的调用方）到template.process(values, output)（FreeMarker服务端模板注入）之间实施并集中复用构造器执行setNewBuiltinClassResolver(TemplateClassResolver.UNRESTRICTED_RESOLVER)显式放开类解析限制。

### 17. hardcoded_secret：src/main/resources/application.yml partners.document-hub段

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

漏洞假设（production client-secret 明文提交、经 @Value 注入并随出站请求携带、泄露可冒用合作伙伴身份）由所给源码直接证实：application.yml partners.document-hub 段明文存有 client-secret=dh_live_Q7m4pN8xK2vL6sR9（client-id=sinkspring-production）；ResourceSyncService 通过 @Value("${partners.document-hub.client-secret}") 注入，并在 loadCatalog 出站 GET 请求中放入 X-Client-Secret 头发送（配置→注入→鉴权头→出站请求链路完整，无加密或外部化凭据管理的任何证据）。secret 作为 document-hub 鉴权凭据离开应用边界，泄露后可用以冒充合作伙伴身份，符合 CWE-798 hardcoded-secret。候选的根因与数据流主张均有对应证据，supported。

#### 修复建议

在src/main/resources/application.yml partners.document-hub段到外部document-hub API的鉴权请求之间实施并集中复用已批准配置中secret无任何加密或外部化处理。

### 18. session_flaw：POST /api/session/login（JSON body为LoginRequest）

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

源码证据支持该漏洞假设的核心分支。SessionService.java 中 openSession 使用编译期常量硬编码单一凭据（OPERATOR_USERNAME="ops-admin"、OPERATOR_PASSWORD="SpringOps#2026"）和 HMAC 签名密钥（SIGNING_KEY="sinkspring-session-key"），并以 Algorithm.HMAC256(SIGNING_KEY) 签发 JWT；常量均为 private static final，application.yml 中无对应配置项，无外部注入/覆盖路径，故"以弱/硬编码密钥签发会话token"由源码直接证明。入口可达性完整成立：POST /api/session/login 映射至 SessionController.login，调用 openSession 后将 token 放入 HTTP 响应（Map.of("token",...)）。凭据校验虽为严格 equals 比较（无效凭据抛 IllegalArgumentException），但"硬编码凭据"与"硬编码低熵签名密钥"使控制失效并造成所调查的 token 伪造/会话接管风险，整体判定 supported。

#### 修复建议

在POST /api/session/login（JSON body为LoginRequest）到HTTP响应中的会话token之间实施并集中复用未知，需验证openSession的凭据校验强度、JWT签名密钥与过期策略。

### 19. object_level_authorization：GET /api/accounts/{accountId}

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

证据链完整证明漏洞假设成立：(1) AccountController.account() 处理 GET /api/accounts/{accountId}，未读取或验证任何会话令牌，仅接收攻击者自声明的 X-Account-Id 头与路径 accountId 后直接调用 accountService.getAccount(requesterId, accountId)；(2) AccountService.getAccount 的方法体仅为 return accountRepository.findById(accountId)，requesterId 未参与任何归属比较、空值或角色校验；(3) AccountRepository.findById 的 SQL 仅以 account_id 作为 WHERE 条件，无 owner/requester 约束，返回 display_name、email、role、notes 等字段。因此 getAccount 确未比较 requesterId 与 accountId 的归属，任何调用者可构造任意 accountId 读取任意账户数据，水平越权（CWE-639）成立。

#### 修复建议

在GET /api/accounts/{accountId}到AccountService.getAccount返回账户数据之间实施并集中复用无可见归属校验。

### 20. arbitrary_file_write：POST /api/documents/content

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

漏洞假设成立。POST /api/documents/content 通过 @RequestBody 绑定 DocumentRequest（仅含 path、content 两个无校验注解字段），直接调用 documentService.storeDocument(request)。storeDocument 使用 documentRoot.resolve(request.getPath()) 构造目标路径：Path.resolve 对绝对路径会直接返回该绝对路径，且代码未做 normalize 或 startsWith(root) 越界检查（对比同文件 loadPublishedDocument 具备 normalize+startsWith 双重校验而写路径没有），随后为父目录 createDirectories 并以 CREATE+TRUNCATE_EXISTING 写入 request.getContent()。攻击者可控的路径与内容均未经任何校验直达文件写入 sink，可在 JVM 进程具备写权限的范围内实现任意文件写入/覆盖，根因、调用链与影响均由所给源码直接证明。

#### 修复建议

在POST /api/documents/content到服务端文件写入之间实施并集中复用无可见上传类型与路径校验。

### 21. arbitrary_file_write：DocumentService.storeDocument(DocumentRequest)

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

证据支持该漏洞假设。DocumentService.storeDocument 中 documentRoot.resolve(request.getPath()) 未做 normalize 或 startsWith(root) 校验；传入 ".." 相对路径可写出 documentRoot，传入绝对路径时 resolve 直接返回绝对路径（忽略根目录）。随后 Files.createDirectories(parent) 可越界创建目录，Files.writeString(CREATE, TRUNCATE_EXISTING) 将请求内容写入/截断覆盖目标文件。DocumentRequest 仅含 path/content 两个无任何校验注解的字段（file:e96bc15b），且 DocumentController POST /api/documents/content 以 @RequestBody 直接反序列化为 DocumentRequest 并调用 storeDocument（file:2857f5e4），无认证/授权/输入校验，因此 path 与 content 确实受请求控制，前提成立。loadPublishedDocument 中存在的 normalize+startsWith 防护在 storeDocument 中缺失，进一步佐证该写入路径无越界控制。

#### 修复建议

在DocumentService.storeDocument(DocumentRequest)到Files.writeString(Path,content,UTF_8)之间实施并集中复用无路径校验与内容白名单，路径穿越可写出documentRoot。

### 22. jndi_injection：GET /api/tools/directory?name=...

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

证据包直接证明了完整数据流：OperationsToolController.directoryEntry 将外部查询参数 `@RequestParam String name` 原样传入 `operationsToolService.lookupDirectory(name)`，而 OperationsToolService.lookupDirectory 无条件执行 `new InitialContext().lookup(name)` 并将结果 String.valueOf 返回。两条源码证据显示该路径上不存在任何校验、白名单、协议/地址限制或拦截，攻击者可控字符串可直接用作 JNDI 名称（如 ldap://... 或 rmi://...），构成攻击者控制的 JNDI 查找（JNDI 注入敏感操作）。漏洞假设（name 进入 JNDI 查找且无防护）由源码直接支持。

#### 修复建议

在GET /api/tools/directory?name=...到lookupDirectory内JNDI查找之间实施并集中复用无协议或地址限制证据。

### 23. jndi_injection：未确认的调用方（OperationsToolService.lookupDirectory）

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

源码证据支持JNDI注入漏洞假设。两条证据闭合了完整路径：(1) OperationsToolController的GET /api/tools/directory以@RequestParam接收name（无认证注解、无校验），直接调用operationsToolService.lookupDirectory(name)；(2) OperationsToolService.lookupDirectory未做任何白名单/协议/格式过滤，直接将name传入new InitialContext().lookup(name)并把String.valueOf(entry)回显给调用者。攻击者可控的name确实到达JNDI lookup敏感操作，控制失效（缺少输入限制）成立。候选标注“未确认的调用方”已被证据包中的控制器证据确认为已确认入口。影响评级（RCE）与说明一致：JNDI lookup指向恶意RMI/LDAP端点是否导致RCE取决于运行时JDK版本与com.sun.jndi.*.object.trustURLCodebase等系统属性，此为环境条件而非漏洞假设的反证；注入漏洞本身（CWE-74，未验证的外部输入进入JNDI查找）已由源码证明。

#### 修复建议

在未确认的调用方（OperationsToolService.lookupDirectory）到InitialContext().lookup(name)（JNDI注入）之间实施并集中复用lookupDirectory未对JNDI名称做白名单或协议限制。

## 待独立复核候选

### unknown：GET /api/navigation/section?name=...

该入口受固定映射约束，输出不可控，无可信攻击路径

- 调查编号：`investigation-3`
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
