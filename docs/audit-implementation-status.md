# 自建审计运行时：实施状态
2026-09-06补充：独立复核恢复链路完成——并行复核完成即落盘（as_completed），复核输入与全部证据指纹（含补证）记录在结果中，续跑时输入与证据一致则标记 reused 跳过重复模型调用，失败占位自动移除重做，验证阶段可原地恢复；候选详情、范围、清单或批次变化均拒绝复用。任务级 token 用量进入导出报告（缺失字段不计 0）。大项目按顶层目录自动拆分 scope 子任务（受 12 上限与预算预留约束），报告新增 scopeCoverage 分组，范围子任务未交付时完成状态压为 partial_report。孤立快照治理：captured_at 时间列、只读报告端点与人工确认后的显式删除（历史绑定永久保留）。增强 for 元素类型推断覆盖标准集合、数组、通配上界、同文件直接/继承链 Iterable 与显式导入；泛型转发与跨文件实现保守保持未知。Java lambda 内 this 沿用外围上下文（JLS 15.27.2），泛型方法上界与重载上界冲突处理已修正。以上均有专项测试与真实容器部署验收；未重建历史索引。
2026-09-06补充：三语言混合仓库（Java+TypeScript+Python）真实链路验收通过：同批次索引成功，Neo4j 中 Python for 循环 list[Item] 元素推断边、TypeScript this 方法返回链边均正确写入；Joern 短暂不可用导致索引失败后恢复并显式 resume 成功。
2026-09-06补充：find_entry_points 新增 cross_language_process 类别（Java：ProcessBuilder/Runtime.exec；Python：subprocess.run/Popen/os.system；Node：child_process exec/spawn/execFile 及同步版本），标记通过子进程调用另一语言可执行文件的跨语言边界，是命令注入跨语言传播的候选路径；只报位置线索，必须read_file核实命令构造。
多Agent最新状态：Web新任务默认3个并发Agent（含主Agent），支持独立基线/架构、专项调查分派、结果回传、共享调用预算、取消和分任务续跑。旧串行任务保持兼容。详见根目录`agent-team-implementation.md`；下方旧测试数量和串行描述是先前阶段记录，不能代替协作验收结果。
2026-09-05补充：子Agent现在可以分批提交候选、反证、未知项和审阅声明。阶段成果先经固定快照与证据引用校验并持久化，再向主Agent精简回注；最终输出失败也不会丢失已经保存的成果。多个具备详情的独立复核使用剩余Agent槽并行运行，每项使用独立模型和证据缓冲，最后由主线程顺序合并。小型订单Demo覆盖运行中提交、去重交付、报告导出、失败覆盖缺口和双候选真实并发屏障。全量回归数量以下方最新测试为准；1个既有Starlette依赖弃用警告。
当前流程、调用图修正及未完成项请先阅读 [当前项目状态](current-project-status.md)。本文按阶段累积，含已过时的测试数字和限制；历史段落中的“最新”不代表当前状态。

历史验证：该阶段369项测试通过，2个FastAPI/Starlette依赖弃用警告，并曾重建API容器；此记录不是当前完整验收结论。
混合搜索、Neo4j和Joern审计工具均已接入。Neo4j保存仓库、快照、文件、符号、`DECLARES`声明关系和Tree-sitter提取的`CALLS`静态调用候选；审计工具提供`find_code_relations`和`find_code_callers`。Java按声明节点绑定调用者，支持重载方法不串线；Python支持`fetch()`与`service.fetch()`这两类直接名称提取。真实Neo4j小样例已验证`demo.Caller.submit()`能定位到`demo.Service.run()`及源码路径、行号，随后只清理该独立测试批次。Joern固定到同一`index_run_id`项目，提供调用位置和参数到调用参数的数据流路径。三类结果都只是线索，必须读取固定源码快照后才能成为证据；模型不能提交任意Cypher或CPGQL。
关系线索现也提供人工可控的Web入口：`POST /api/code-graph/symbols`、`POST /api/code-graph/callers`和`POST /api/code-graph/callees`必须显式提交仓库、快照和索引批次，不暗中选择最新版本。Agent对应拥有声明、向上查调用者、向下查目标三种只读工具。真实HTTP小样例从两个方向都返回`webdemo.Controller.submit() -> webdemo.Service.run()`及路径、行号，随后确认测试快照残留为0。
静态调用精度新增第一层过滤：调用记录包含源码行、可直接确认的接收者类型和参数个数。`new SecondService().run()`、静态类型接收者、`this`和同类内调用会用类型缩小候选，Java重载再按参数个数过滤；普通变量类型未知时不猜。含两个类三个同名/重载`run`的真实Neo4j与HTTP反例只返回`SecondService.run()`一条边，同时返回调用行和声明行。仍未实现完整变量类型推断、继承及动态分派。
Java普通变量进一步支持明确声明的字段、方法参数和局部变量，并按“局部变量 > 参数 > 字段”处理遮蔽。`var`或泛型类型变量即使类型未知也会正确遮蔽同名字段，不会错误回退。真实Neo4j/HTTP小样例同时验证字段调用连接`FirstService.run()`，同名参数和局部变量调用连接`SecondService.run()`，三条边均无跨类误连；测试批次随后清理为0。方法返回值链、Lambda推断和继承分派仍待完善。
增强`for`变量、try-with-resources资源和`catch`参数现也按各自词法作用域解析。测试覆盖离开循环、资源或catch作用域后恢复同名字段类型；真实Neo4j/HTTP循环反例在内部连接`RightService.run()`、循环后连接`WrongService.run()`，行号分别准确返回7和8，随后测试批次清理为0。Lambda推断、跨文件方法返回、继承和接口动态分派仍未实现。
同一源码文件的方法返回值链现可解析：先按接收者类型、方法名和参数个数找到唯一声明，再把明确返回类型交给外层调用。真实Neo4j/HTTP反例中`factory.service().run()`只连接`Factory.service()`和`RightService.run()`，没有误连`service(String)`或`WrongService.run()`，并返回调用行与两个目标声明行；测试批次随后清理为0。返回类型冲突、Lambda、继承和接口动态分派仍保持未知。
跨文件返回值链进一步在仓库汇总阶段补全：单文件调用记录保留返回方法的所属类型、名称和参数个数，所有成功文件处理结束后汇总方法返回类型，只在结果唯一时填入原本未知的接收者。两个短名相同的`Factory.service()`返回不同类型时保持未知。真实Docker链路扫描`Controller.java`与`Factory.java`两个临时文件、0错误，Neo4j/Web跨文件返回`Factory.service()`与`RightService.run()`且不含`WrongService.run()`；临时目录自动移除，测试图随后清理为0。Lambda、继承及接口动态分派仍待实现。
包名/import限定现按显式import、同包类型、唯一通配import和仓库全局唯一短名依次解析；Neo4j符号与调用关系保存所属类型完整名，有完整名时只按完整名连接。真实三文件Docker反例同时声明`first.Factory`和`second.Factory`，`import first.Factory`后只返回`first.Factory.service()`及`first.RightService.run()`，结果不含任何`second.*`边；测试图清理为0。静态import、嵌套类型import和依赖库外部类型不会伪装成已解析。
Java类型关系新增`EXTENDS`、`IMPLEMENTS`和`OVERRIDES`。类/接口声明块保存父类型原始名，仓库汇总阶段按import和包名解析后写入Neo4j；方法块继承所属类型的祖先集，方法名和参数个数匹配时生成覆盖边。真实Docker三文件链路确认`Service EXTENDS Base`、`Service IMPLEMENTS Greeter`、`Service.greet() OVERRIDES Base.greet()`和`Greeter.greet()`；新增`POST /api/code-graph/type-relations`返回这些行。测试图随后清理为0。未解析的外部类型不会生成边。
动态分派候选新增`POST /api/code-graph/dispatch-targets`和Agent工具`find_dispatch_targets`：按方法短名定位仓库内基础声明，收集所有直接`OVERRIDES`实现。真实Docker接口/双实现反例返回`Greeter.greet()`的候选为`AService.greet()`和`BService.greet()`；普通实现方法标记为`no_in_repo_overrides`。候选来自仓库内边，外部实现缺失时不代表没有其他运行时实现；测试图随后清理为0。
继承方法返回值链补全：子类型没有重新声明的方法在仓库汇总阶段登记祖先的唯一返回类型；`Mid extends Base`时`mid.service().run()`现在能解析为`Base.service() -> RightService`，真实Docker链路只返回`inherit.RightService.run()`且不含`WrongService.run()`。子类型自己声明同名方法时不继承，方法未声明时不会伪造声明块；测试图清理为0。
类型关系已接入Agent只读工具`find_code_type_relations(symbol,limit)`：与其它图工具一样先固定源码绑定批次，返回`EXTENDS`/`IMPLEMENTS`/`OVERRIDES`行并按范围过滤。真实Docker容器链路确认`scope_info`会声明该工具，且`Service`查询返回`agenttool.Service EXTENDS agenttool.Base`；测试索引批次与Neo4j测试图随后清理。至此Agent可用的图工具共五类：声明、向上调用者、向下目标、类型关系和动态分派候选。
Python类型关系补齐：类声明块保存基类短名，仓库汇总阶段按全局唯一短名解析成`EXTENDS`边；函数块继承所属类的祖先集并生成`OVERRIDES`。有基类无法唯一确认（同名冲突或外部类）时整体保持未知，不做部分猜测。真实Docker链路确认`Service EXTENDS Base`和`Service.greet OVERRIDES Base.greet`均正确生成；Neo4j OVERRIDES匹配对无参函数（parameter_count为空）不再过滤。测试图随后清理为0。
Python接收者类型推断补齐：`self.service.fetch()`按`__init__`中`self.service = 参数`与参数注解`service: OrderService`解析为`OrderService`；带注解局部变量`local: OrderService = service`同样支持。`__init__`属性查找的搜索范围使用文件级语法树，避免只搜当前函数体漏掉类定义。真实Docker链路确认`Controller.submit`到`OrderService.fetch`的调用边携带正确接收者类型，测试图随后清理为0。无注解变量、`var`推断、动态工厂返回值仍保持未知。
动态分派候选新增`receiver_type`过滤：调用点能确认接收者类型时（Java重载已解析、Python注解变量等），候选只保留该类型及其祖先声明的同名方法；接收者类型解析为多个同名声明时返回空，避免猜测。真实Docker反例中仓库同时有`Greeter.greet()`、`AService.greet()`和无关`Unrelated.greet()`，不带过滤返回全部3条，`receiver_type=Greeter`时只返回`Greeter.greet()`及其实现`AService.greet()`；Web接口与Agent工具`find_dispatch_targets`均支持该参数，测试图随后清理为0。
新增代码关系查询页面`GET /graph`和`GET /api/repositories/index-runs`：页面按仓库/快照选择后列出仍有源码绑定的索引批次，再按符号查询声明、调用者、调用目标、类型关系和分派候选；只返回位置线索与限制说明，不显示源码正文。真实Docker验证页面200、17个已索引仓库可选、混合语言仓库的批次列表与符号查询正常返回。仍不含源码内容与任意查询入口。
Agent工具提示词新增关系图使用顺序：先用`find_code_relations`定位符号声明，再用`find_code_callers`/`find_code_callees`沿调用方向展开，需要继承链或动态分派时用`find_code_type_relations`和`find_dispatch_targets`（可带`receiver_type`收窄）。该顺序写入共享工具说明，基线、主调查、独立复核和子Agent使用同一版本；真实容器验证提示词已包含该顺序。这是策略提示，不是执行保证。
框架入口识别补充程序式注册：Flask `add_url_rule`与FastAPI `add_api_route`/`add_websocket_api_route`现在返回`fastapi_flask`路由线索，标记为`add_*_route`。真实Docker容器用固定快照验证两种注册方式均能定位到行号；普通`add_record`等无关调用不误报。装饰器识别边界与限制说明不变，仍需`read_file`核实路由与鉴权。
入口识别与关系图已确认可组合：入口标记的路径、行号落在对应方法块的行号区间内，同一批次上从入口方法继续`find_code_callees`展开能直接命中下游调用边（真实Docker链路验证`list() -> Service.find()`）。典型工作流即`find_entry_points`定位入口、再沿调用方向展开排查，两层结果行号可互相印证。
Spring入口识别扩展：`@Bean`（bean_definition）、`@EventListener`（event_listener）、`@KafkaListener`/`@RabbitListener`（message_consumer）、`@Scheduled`（scheduler）及`RouterFunction`函数式路由现已覆盖。真实Docker容器固定快照验证`@Bean`、`RouterFunction`、`@Scheduled`均能定位行号；这些入口不经过`@GetMapping`装饰器，此前会整体漏掉，对安全审计是重要盲区（消息消费者与定时任务同样承载不可信输入）。
`find_entry_points`工具说明同步更新为新标记清单；真实容器验证Agent提示词已包含更新后的描述。
修复Java可变参数方法的调用边漏报：`String... parts`声明现记录varargs属性，参数计数过滤放宽为"实参个数≥声明个数"。真实Neo4j隔离验证`log("a","b")`（2实参）此前被过滤、现在正确生成边。同批次多条同名调用在图上合并为一条边属Neo4j MERGE语义，边属性保留首次调用信息。varargs限制从文档已知盲点升级为已修复并实证。
修复Python同名函数调用边的参数数量误配：旧查询先用Java字段`parameter_count IS NULL`放行，而Python该字段本来为空，导致Python专用过滤被绕过。现按语言属性分支，函数块分别保存最少参数、最多参数和`*args`能力，并排除方法自动传入的`self`/`cls`。真实Neo4j隔离Demo中`log(msg, level=1)`的一参数调用和`many(*args)`的三参数调用正常生成边，`zero()`被错误传入三个参数时不再生成边；测试批次随后精确清理。
Python关键字参数匹配继续细化：调用记录区分位置参数、明确关键字名称和`*`/`**`动态展开；函数声明记录位置参数上限、可接收关键字名、必填仅关键字参数和`**kwargs`能力。真实Docker端到端Demo经过临时源码扫描、Tree-sitter切块和Neo4j写边，确认`def f(*, token)`不匹配`f(1)`，`def f(value, /)`不匹配`f(value=1)`，合法形式和`**kwargs`正常连接；动态展开因运行时值未知而保守保留候选。临时源码和图批次均已精确清理。
Python跨文件类型现使用模块限定符号名，例如`first/service.py`中的类保存为`first.service.OrderService`。仓库汇总阶段解析显式导入、`as`类型别名、模块别名和相对导入，并为参数注解与`module.Type()`构造调用补全接收者完整名。真实Docker端到端Demo同时声明两个模块的同名`OrderService`，`controller.first_call`和模块构造调用只连接`first.service.OrderService.fetch`，类型别名调用只连接`second.service.OrderService.fetch`，没有跨连；合成图随后精确清理。没有import且短名冲突时保持未知，动态import和星号导入仍不猜测。
Python跨文件返回类型链已接入同一仓库汇总流程：函数块保存`-> Type`返回注解，外层链式调用保存接收者方法的所属类型、方法名和实参数量；返回类型能按模块/import唯一解析时才回填。真实Docker源码→Tree-sitter→Neo4j链路确认`controller.handle`同时连接`factory.Factory.create_service`和返回类型上的`services.OrderService.fetch`，工厂方法自身连接构造类型；无import且返回短名冲突的反例保持未知。合成图随后精确清理。
Python继承返回链进一步复用祖先闭包：子类没有重写方法时登记父类的唯一返回类型，子类声明同名方法时以子类返回注解为准，多个祖先返回冲突时保持未知。真实Docker链路验证`ChildFactory`未声明`create()`时，`controller.handle`同时生成到`base.BaseFactory.create`和`services.Service.run`的调用边；为此Neo4j接收者完整类型匹配也允许沿已确认的`EXTENDS`/`IMPLEMENTS`关系定位祖先方法。合成图随后精确清理。
模型适配器新增显式`SECVAL_AUDIT_TOOL_PROTOCOL=native`模式，向OpenAI兼容Chat Completions发送统一目录生成的只读取证函数声明，校验每轮单个`tool_calls`，并在下一请求用原`tool_call_id`和`role=tool`回传结果。后端内部及检查点仍保存供应商无关的标准动作，恢复时不伪造丢失的原生调用状态；记录边界、调查和报告继续使用严格JSON契约。默认保持`json`兼容模式，原生与流式同时配置会明确拒绝，未替用户切换当前供应商，也未为此调用真实模型。
原生工具协议现可跨进程恢复：检查点仍只保存供应商无关的标准工具动作和结果；新模型实例会从相邻记录重建一组稳定、成对的`assistant tool_calls`与`tool`消息。当前任务已经移除的工具不会因旧检查点而恢复。进程未重启时继续沿用供应商原始调用编号；重启后使用本地确定性编号，只用于同一次请求内配对，不冒充供应商保存的历史状态。
审计测试页面补齐报告收口展示：任务进入needs_review、failed、cancelled、interrupted或budget_exhausted后，页面直接读取导出接口并显示`completion.state`和`pendingReasons`，不再把部分报告与已登记检查项收口混在完整JSON里。续跑按钮复用同一组调用/时长预算输入。页面参数由离线路由测试锁定，真实容器页面已复查包含新提示。
## 真实模型团队协作验收（2026-09-06）
团队orders合成Demo已通过正式Web接口完整运行：上传、索引、混合搜索3项命中、3个并发Agent协作审计，38次真实模型调用后提交报告（needs_review/report_submitted）。合成仓库`secval-web-check-d1b14226baf44af3a0d25499965b36d2`保留供页面查看，没有删除或覆盖用户索引。
核心结论符合预期：OrderService.fetch缺少归属校验被列为supported候选并附文件证据；SafeOrderService被正确当作反证对照；快照内无调用者/入口被如实列为可达性未知，而不是直接宣称可利用。报告为partial_report：存在待收口调查和未登记文件审阅声明，完整覆盖未声明。
验收过程中暴露并修复两个问题：1）run_web_check脚本此前调用同步索引接口，Joern超时会导致脚本退出且manifest永远停在index阶段；现已改为后台索引任务轮询，失败会落盘具体阶段和错误。2）Joern夜间版容器在连续多次导入后REPL线程挂起（StackOverflowError后CPU归零），600秒超时触发，索引按设计回滚；重启Joern容器后同一任务显式续跑立即成功。失败仓库a680144e...及其失败任务80168a56...保留作为证据。
部分报告显式续跑已完成真实验收：父任务38次调用提交partial_report后，通过`POST /api/audits/{id}/resume`创建子任务，子任务从检查点继续25次调用后再次提交报告；父报告未被修改，子报告记录parentTaskId与priorModelCalls=38。核心候选从"supported发现"降级为"已登记候选发现detail-2（medium/medium）待独立复核"，调查经两次同模型静态复核维持inconclusive，这与快照内无调用者/入口的事实一致，没有把控制缺失直接升级成已确认漏洞。
新发现的预算调度缺陷及修复（已含真实验收）：独立复核子任务agent-3因"为主调查保留预算"（stop_reason=reserved_for_main）在10次调用后停止且未返回结果。修复后真实续跑确认：第三次续跑任务1aa0449d（prior=63）中agent-3被恢复并真正完成（3次调用），独立重读两个源文件后确认代码层缺陷成立、可达性维持inconclusive；worker_step_limit触发的新agent-4仍保留为覆盖缺口。
正式"独立上下文证据包复核"（independent_context_packet_review）已完成真实模型验收：新增带Spring入口的合成用例order_entry（@RestController直连无归属校验的服务，入口在快照内），调查达到supported并触发正式复核。首次验收暴露第二个预算缺陷：主调查用尽全部40次预算后，review通道在step_limit被拒，复核静默失败为"复核未完成"。已修复：review通道不受step_limit和主调查预留限制，可消费全部剩余预算；报告阶段的主调查在复核待执行时不能占用最后一次调用（reserved_for_review）。修复后真实续跑任务e59b53c4（prior=40）中复核真正执行：对证据包返回supported，逐条核对四个源文件的根因/数据流/sink/影响主张，明确把"Repository实现类不在快照内"列为未完全排除的反证而非否定，orderId可枚举性未被推定；候选按详情指纹提升为正式发现svf_29587aaa（static_supported_needs_review）。合成仓库secval-web-check-c595c457...保留供页面核对。
验收demo的入口识别已由回归测试锁定：order_entry的OrderController（@RestController+@GetMapping）在真实清单布局下能被find_entry_points识别为controller/route入口；该识别退化会让supported→独立复核验收链路失效，测试会先失败报警。
框架入口识别新增安全边界类别：Servlet @WebFilter、implements Filter、extends OncePerRequestFilter、implements HandlerInterceptor和extends HandlerInterceptorAdapter现在作为security_boundary返回（framework=spring）。过滤器/拦截器在请求到达控制器前生效，识别它们后模型才能核对"有效策略"而不只看注解路由。正则按词边界和完整类名匹配，implements ResultSetFactory这类含Filter子串的名字不会误报。两项正反回归测试覆盖。
工具目录说明已同步security_boundary能力：find_entry_points的描述现在明确告知模型返回过滤器/拦截器边界，并提示核对有效授权策略时应检查这些边界而不只看注解路由。离线回归确认363项通过，API容器已部署更新。
Python侧安全边界识别补齐：FastAPI/Flask的add_middleware、@app.middleware装饰器和类名以Middleware结尾的中间件类（含Django风格）现在同样作为security_boundary返回。普通业务类（如OrderService）不会因class声明误报，正反回归测试覆盖；工具目录说明同步提及Python中间件。隔离回归365项通过后部署API容器。
安全边界能力已完成真实模型链路验收：在order_entry demo基础上增加AuthConfig.java（返回Filter类型的authFilter工厂方法，仅校验Authorization头非空、无归属授权、无注册注解）。真实审计中模型读取过滤器逻辑，将"过滤器构成有效防护"作为反向防护假设判为refuted（附反证：仅验证头存在性≠身份解析与归属授权；注册绑定无源码证据），主调查的归属校验缺失候选经独立上下文复核supported后按详情指纹提升为正式发现svf_c074b545。报告存档于data/web-audit-checks/boundary-check/。同时补充demo保护测试：AuthConfig工厂方法（Filter类型返回）命中security_boundary，OrderController注解识别互不干扰；实现新增工厂方法形态（Filter 方法名()）的识别规则。隔离回归366项通过。
Python侧安全边界真实链路验收：新增orders_api合成FastAPI项目（AuthMiddleware仅检查Authorization头非空+get_order接口无归属校验），完整走Web链路。真实审计确认模型使用find_entry_points识别出唯一业务入口与AuthMiddleware安全边界，正确判定中间件仅验证头存在性不构成归属授权（两级授权均缺失，BOLA候选成立）。首跑40次预算在调查阶段耗尽（budget_exhausted），检查点完整保存（investigation-1:supported、2条证据、2个文件审阅），显式续跑（prior=40）后主调查完成并进入验证阶段；独立复核请求失败（网络或响应限制），按设计记为inconclusive并把候选保留在needs_review，不冒充完成复核。报告存档于data/web-audit-checks/py-boundary-check/。本次同时验证了budget_exhausted→resume的真实闭环。
仓库治理收尾：.gitignore放行order_entry与orders_api两个验收demo目录及docs/audit-agent.md，验收用例不再只存在于工作区；新增orders_api Python demo保护测试（路由+中间件双命中，顺序不敏感）。隔离回归367项通过，API容器已部署。至此Java与Python两侧的安全边界能力均有：识别规则、工具说明、demo保护测试、真实模型全链路验收四层证据。
续跑预算策略优化（已含真实验证）：多次真实续跑观察到"续跑预算被恢复的旧子任务完整重跑吞掉"（15次续跑预算因此耗尽）。已修复：续跑时因reserved_for_main或worker_step_limit暂停的子任务不再立即恢复重跑，保持stopped状态，由主调查在报告前按需收尾；真实失败（模型请求/输出/证据服务错误）者仍恢复独立对话续跑。真实验证：py-boundary任务链第四代（prior=106）续跑20次调用即完成主调查收尾并进入验证阶段（此前同等进展需30-40次）。第五代（prior=126）仅用4次调用完成收口：独立复核真正执行并返回supported——逐条核对处理器未读会话身份、未比较owner_user_id、无Depends授权依赖，并明确"中间件仅认证性检查，即使完整生效也不弥补对象级授权缺失"；候选提升为正式发现svf_e60124a9。Python侧supported→独立复核→正式发现全链路至此完整闭环，两次失败复核均被如实记录为缺口而非伪装成功。报告存档于data/web-audit-checks/py-boundary-check/。
负样本（误报控制）真实验收完成：新增orders_safe合成仓库（Depends注入会话身份+return前比较owner_user_id抛403），走完整Web链路。模型正确判定IDOR假设为refuted——核实归属比较位于return之前且无绕过分支、与用户业务规则一致；未提交任何漏洞发现（findings=0），没有为完整防护的代码制造supported候选。同时如实保留缺口：基线子任务因JSON格式错误失败、文件审阅为partial，报告仍为partial_report而非宣称完整。正样本（orders_api/team_orders/order_entry）与负样本（orders_safe）双向验收至此齐备，误报控制有真实模型证据。23次调用，报告存档于data/web-audit-checks/orders-safe-check/。
仓库治理补齐：.gitignore放行orders_safe负样本demo；新增其入口识别保护测试（@app.get路由命中）。三个验收demo（order_entry/orders_api/orders_safe）与对应保护测试全部可复现，正负双向链路的每一环节都有识别规则、工具说明、保护测试、真实模型验收四层证据。
Python侧独立复核闭环完成：对partial_report再续跑两代（15次预算再耗尽一次、续跑prior=76后第三次30次预算完成），正式独立上下文复核返回supported：复核确认处理器未读取会话身份、未比较owner_user_id，并明确指出"对象级授权缺失与中间件强度无关，即使中间件完美验证令牌处理器仍无归属校验"；复核limitations如实列出旧式get_response签名在FastAPI下的运行行为未验证、小整数ID不证明可枚举等六项。候选按详情指纹提升为正式发现svf_e60124a9（idor，static_supported_needs_review）。安全边界能力至此在Java与Python两种语言均完成supported→独立复核→正式发现的完整真实模型验收。三次任务链40+15+30=85次调用，父报告均未被修改。
原生工具声明进一步按每个任务固定`scope_info.tools`裁剪：没有Neo4j、Joern、混合搜索或源码绑定能力的任务不会把对应函数发送给模型；主调查、基线、子Agent和独立复核在各自模型实例请求前使用同一任务范围。未知工具名被忽略，空能力集合不发送空`tools`字段，模型返回未授权原生工具时仍由适配器与后端双重拒绝。
新增只读`GET /api/audit-settings`与审计页面运行配置提示，展示模型名、工具协议、流式开关、单次超时、输出上限和连接是否就绪。接口只计算地址与密钥是否为空，不返回两者正文；用户无需进入容器即可确认正式审计会使用哪种模式。
Python异步入口识别补齐：Celery `@celery.task`/`@app.task`、Django `@shared_task`与`@receiver`信号、FastAPI `@app.on_event`现已识别为`async_entry`，与Java消息/定时/事件入口对称。真实Docker容器固定快照验证`@celery.task`与`@receiver`定位正确；`@app.get`路由与`@functools.lru_cache`等普通装饰器不误报。至此两类语言的入口面覆盖对齐：HTTP、消息/任务队列、事件信号、定时任务。
Python侧组合性同样验证通过：`@app.get`入口行号与`list_orders`函数块区间吻合，同一批次展开得到构造调用`OrderService()`与带接收者类型的下游边`OrderService.find`（构造表达式可直接确认类型）。Java与Python的入口→关系工作流均已实证。
程序式注册进一步支持嵌套命名空间：`api.v1.add_api_route(...)`这类多级属性对象现已覆盖；真实Docker容器固定快照验证嵌套写法定位正确，普通调用仍不误报。
审计页面新增“打开代码关系查询”入口，从任务页面可直达`/graph`核对同一批次的关系线索；工具说明同步标注`find_entry_points`支持程序式路由注册。真实容器验证审计页面200且入口链接存在。
审计报告新增`graphQuery`字段：报告导出自动携带仓库、快照、绑定的`index_run_id`及页面提示，人工复核可直接在`/graph`选择同批次核对关系线索；无绑定批次时该字段为空由页面提示。真实容器验证导出内容正确。
修复Java接口继承接口被漏掉的缺陷：当前tree_sitter-java版本的`extends_interfaces`节点未标记为field，`child_by_field_name`返回None导致`interface Child extends Parent`的父接口丢失。现改为按节点类型查找。真实Neo4j链路确认`Child EXTENDS Parent`与`Impl IMPLEMENTS Child`均正确生成，测试图清理为0。
真实链路核对Java特殊声明：enum/record实现接口并覆盖方法时祖先闭包与OVERRIDES边均正确；接口default方法未被重写时调用边正确落到接口声明本身。本阶段曾发现可变参数方法多传实参会丢边，后续已经按上文记录修复并做真实Neo4j验证。
部署验收时发现Joern JVM在连续分析后发生明确的`OutOfMemoryError`，旧实现又用600秒分析超时执行启动探针，使整个Web API卡在启动。现Web启动不再同步访问Joern，健康接口使用独立5秒超时，Docker探针限制10秒；大型分析仍保留600秒任务超时。Joern堆上限由2G调整为4G并重建，持久化工作区未删除；API与Joern当前均健康。这是可用性隔离，不代表Joern OOM根因已从上游消除。
耗时索引新增持久化后台任务接口`/api/repositories/index-jobs`：创建立即返回任务编号，页面轮询状态和当前阶段；服务重启把未完成任务标为`interrupted`，只能显式调用`/resume`创建子任务重跑。原同步接口保留兼容。后台真实合成验收从`queued`完成到`completed`，写入6个块；当前完整回归250项通过。
2026-09-05多语言更新：新增Python Tree-sitter解析与文件头/类/函数/异步函数切块，扫描、固定源码快照、审计正文权限使用同一支持扩展名集合。纯Python订单Demo通过正式Web上传与后台索引，生成4个搜索块，Neo4j查到2条相关声明，Joern查到1个调用点，强制重建Joern容器后调用点仍存在。
Java/Python混合Demo进一步暴露并修复Joern只选一种前端的问题：现按语言建立`index_run_id-java`/`index_run_id-python`子项目，查询时从持久工作区发现并合并结果。真实验收同时得到1个Java `equals`调用和1个Python `fetch`调用；旧单项目在新批次绑定后才删除，强制重建Joern容器后两个子项目仍可查。当前不会自动连接跨语言调用边。完整回归255项通过。
框架入口新增`find_entry_points`固定快照工具，目前识别Spring、JAX-RS、FastAPI/Flask和Django常见路由标记。结果只返回框架、类型、标记、路径和行号，不返回源码、不直接形成漏洞证据。已通过正式PIT与Python Demo实测定位1个路由，并用反例防止`@ControllerAdvice`/`@PathParam`被误判。完整回归260项通过。
后台索引新增操作系统文件锁。后台接口与旧同步接口共用同一把锁，因此同一台主机上即使启动多个API进程，也只能有一个进程执行“写入新索引并清理旧索引”的完整流程。进程异常退出时操作系统会释放锁；只有成功取得锁的进程才会把遗留任务标记为`interrupted`。审计任务使用另一把同类锁，第二个API进程启动时不会再误伤正在运行的审计；取消后要等已经发出的请求退出才释放锁。这不是分布式任务队列，也不负责跨主机排队。索引任务现记录创建、开始、结束时间、完整阶段历史及失败阶段；旧记录缺少真实时间时保持为空。新增SQLite取消信号：执行进程在提交前的阶段边界安全停止，绑定或清理阶段拒绝取消，已取消任务可显式续跑。任务由工作进程原子认领，保存执行者、尝试次数、心跳和租约到期时间；长步骤由独立线程续租，终态清空租约。租约目前只用于所有权和失联证据，不自动抢占。恢复扫描已改为直接查询所有未完成任务，不再受100条列表分页影响。真实Web验收显示正常任务“绑定新索引与源码”先于“清理旧索引”；取消任务没有产生新快照，旧快照仍可查询；认领任务运行和结束字段符合预期。当前完整回归271项通过。
审计长任务也已加入原子认领、执行者、尝试次数、后台心跳和租约。运行信息放在独立`audit_task_runtime`表，调查正文与证据仍在原任务JSON中，避免心跳覆盖审计进度。跨进程取消只写运行表，模型与子Agent通过合并视图看到`cancelled`后停止；已发送请求退出时再固定最终取消状态并释放租约。测试覆盖慢模型请求期间持续续租、第二个Store取消、调查字段不丢失、三个并发请求结果冻结，以及认领前取消竞态。旧任务自动补运行表，未知历史执行者保持为空。
索引和审计均新增`pending/healthy/expired/inactive/missing`租约诊断及显式`recover-stale`接口。恢复必须同时满足租约过期和操作系统进程锁无人持有；成功后只收口为`interrupted`或`cancelled`，不会自动执行索引、调用模型或建立续跑任务。真实HTTP使用无源码合成记录验证两类失联任务均从`expired`变为`interrupted/inactive`且保留尝试次数。当前完整回归277项通过，最新API已部署且旧任务元数据查询兼容。
索引任务从“单任务互斥”升级为持久化队列：Web创建立即入库，忙碌时显示`queue_position`，空闲Worker按创建顺序原子认领并连续消费；同一时间仍只有一个索引在执行。真实Docker验收：外部进程持锁时提交两个任务分别排队1、2位，锁释放后无需新请求即顺序完成且第二项开始晚于第一项结束。重启语义经真实容器验证：queued任务被新服务自动消费；running任务正确中断，显式resume后子任务成功。当前完整回归278项通过。
审计任务复用同一队列模式：创建请求只做只读预检并入库，模型与取证工具在Worker认领后才创建；同一时间仍只执行一个审计。真实Docker验收：外部进程持锁时提交两个合成审计任务均保持queued，锁释放后同一Worker顺序执行；第一项按预算收口`budget_exhausted`（3次调用），第二项自动开始并同样在预算点收口，全程租约healthy且结束后清空。排队任务取消会直接收口，重启保留queued。当前完整回归278项通过。
新增统一队列可观测性：审计任务详情返回`queue_position`，`GET /api/task-queues`返回索引与审计各自的queued/running深度。真实API返回`{"index":{"queued":0,"running":0},"audit":{"queued":0,"running":0}}`。当前完整回归281项通过，最新API已部署。
Python 返回注解链新增两类保护：`Factory().create().fetch()` 会先把外层调用记录为“接收者来自 `Factory.create(0参数)`”，仓库汇总阶段再根据 `create() -> Service` 唯一回填为 `Service.fetch`；拆行的 `service = Factory().create()`、`service.fetch()` 也能沿同一返回类型表补全。变量若可能在分支中重赋值则保持未知，避免把运行时不确定路径误连为确定调用边。完整回归 372 项通过，2 个警告均来自 FastAPI/Starlette 的既有弃用提示。

新增 JavaScript 第一阶段完整处理链：`.js` 已接入扫描、安全读取、Tree-sitter 语法校验、文件头/类/方法/普通函数/单变量箭头函数切块和基础调用记录；Joern项目名与按语言快照目录同步放行 `javascript`。Express/Koa 风格的 app/router/api/server 路由对象可由 `find_entry_points(framework="express_koa")` 定位，`.use(...)` 作为待核实的安全边界线索；普通 `service.post(...)` 反例不会误报。语法错误隔离、箭头表达式函数体、路由正反例均有测试，完整回归 376 项通过。当前不含 TypeScript、跨文件模块类型解析、对象字面量方法和动态原型语义，不能宣称与 Java/Python 精度相同。

JavaScript正式Docker链路已用`orders_js`小型合成项目验证：Web ZIP上传1个文件后，后台任务`f97b32d81f2f42699985329a66eb281a`完成，批次`fb5366b8-e6c9-478a-ad57-4fd8a2808773`生成5个块和5个向量、失败文件0、删除旧块0；阶段记录证明先绑定新索引与源码，再清理旧索引。混合搜索返回5项`server.js`结果；Neo4j找到`server.OrderService`声明并生成`server.getOrder -> server.OrderService.find`调用边（调用行21）；Joern找到`loadOrder`调用位置`server.js:14`。合成仓库`secval-js-check-9425093050d74dbd807350133cf5d9d9`保留供页面复核。demo入口和Joern项目名已补保护测试，完整回归378项通过。

新增 TypeScript/TSX 第一阶段完整处理链：扫描映射重构为“扩展名→语言”，`.ts`与`.tsx`共享`typescript`语言但使用各自Tree-sitter语法；切块复用JavaScript主体规则并增加interface/enum/type_alias。入口工具新增`nestjs`筛选，识别@Controller、HTTP方法、@MessagePattern/@EventPattern、@Cron、@UseGuards和NestMiddleware；`.ts`中的Express路由也支持，普通service.post反例不误报。随后补充参数类型、显式局部类型、`new`表达式和NestJS构造函数参数属性的接收者推断；静态ES Module命名导入及别名可以解析到仓库内完整类型。普通构造函数参数不会被误当成`this`属性。动态/有歧义的默认导入、接口继承、泛型约束、装饰器参数语义和依赖注入运行时绑定仍不推断。

TypeScript正式Docker链路已用`orders_ts`单文件NestJS合成项目验证：后台任务`9b5124d3580e4a32a80cbc3667746472`完成，批次`5f5d2f02-c525-441c-be71-fd8414cfd357`生成9个块和9个向量、失败文件0、删除旧块0，Joern TypeScript项目真实导入成功。混合搜索返回5个相关符号；Neo4j生成`orders.controller.OrderController.getOrder -> orders.controller.OrderService.find`调用边（调用行27）；Joern定位`loadOrder`到`orders.controller.ts:16`。合成仓库`secval-ts-check-577d7b55360f4ec39b6a8f1cb2aec32e`保留供页面复核。完整回归384项通过，2个警告仍为既有依赖弃用提示。

同一TypeScript合成仓库完成再次替换索引验收，当前批次为`e25ef270-7108-4931-be4b-52e0f706ca70`。源码绑定新增`active`状态：当前批次列表只显示新批次，旧批次不再被新审计误选；旧绑定记录及源码快照不删除，历史审计仍可解析原证据。只有OpenSearch、Qdrant、Neo4j和Joern旧数据清理均成功后才停用旧批次，任一可选索引清理失败则旧批次继续显示，避免把未完成的替换冒充成功。真实Neo4j查询确认`this.orderService.find()`的接收者类型为`OrderService`，完整类型为`orders.controller.OrderService`。

TypeScript类型关系已接入已有关系图流水线：`interface extends`记录为`EXTENDS`，`class implements`记录为`IMPLEMENTS`，静态命名导入别名可解析完整父类型并建立祖先闭包；重复短名且无明确导入时不建边。条件类型中的`extends`和字符串中的`implements`不会被误当成声明关系。暂不生成TypeScript `OVERRIDES`，因为还需先完成方法参数签名与重载消歧。当前完整回归392项通过，2个警告为既有依赖弃用提示。

正式Docker链路另用两文件`typescript_relations`小Demo验收：任务`2ae32ceb101d4aeaa7b0a6adf4e18482`、批次`a6ccc218-9ecc-40c6-ba4d-5944b9a9f2b6`完成，生成7个代码块和7个向量且无失败文件。Neo4j真实查询返回`service.OrderService -[:IMPLEMENTS]-> contracts.OrderContract`及`contracts.OrderContract -[:EXTENDS]-> contracts.RootContract`。合成仓库`secval-ts-relations-b69e75b15fe1448ab82c79e442eccdfd`保留供页面复核；没有使用或替换用户真实仓库。

TypeScript接口方法签名现单独建符号并保存参数数量，类方法祖先链可生成`OVERRIDES`候选。首次正式替换任务`969deff59af0487aae76a48319ee2bd7`在Joern阶段因历史项目长期保持open导致Java堆OOM；任务明确失败，当前选择器仍只显示旧成功批次，证明半成品未绑定、旧批次未删除。Joern客户端随后改为导入保存后立即close，只读查询也在同一服务端语句内open、读取并close；持久项目不删除。重启已耗尽内存的Joern后，通过正式resume创建子任务`0ce8251dc77645c7b65d265fe61e14fb`，新批次`2d730407-029f-497d-8a51-aa0b8d8218ac`成功生成9块/9向量。真实查询返回`OrderService.find -> OrderContract.find`和跨祖先链的`OrderService.check -> RootContract.check`重写候选；工作区核对全部项目open状态为false。当前完整回归394项通过，2个警告为既有依赖弃用提示。

Joern锁超时现覆盖“等待客户端锁+剩余HTTP请求”的同一总预算，短健康探针不会在长分析后面无限等待。导入的`importCode/校验/ossdataflow/save/close`由可重入锁包成一个不可交错序列，避免审计查询在步骤间切换Joern全局活动项目；并发测试确认导入步骤间的健康探针按短超时退出。该锁仍是单API进程内保护，不冒充跨进程协调。

TypeScript参数进一步区分固定参数总数、必填参数数和rest。调用边使用参数区间，可选/默认参数可省略，rest可接收更多实参；Java varargs最低实参数也修正为固定参数数减一。`OVERRIDES`对TypeScript采用保守的总数、必填数和rest形状一致规则。具体接收者存在兼容方法时只连接具体方法，找不到时才回退祖先声明，避免同时返回实现与接口重复候选。三文件合成仓库`secval-ts-optional-218ba0f1398b48e4bb14e075cd8d8cb3`正式任务`2faf19117e1b47388854598ae77e86d3`、批次`8d29a504-8e66-489b-b909-46f8bc2b0488`完成，15块/15向量、失败文件0。一参和二参调用均只连接`service.OrderService.find`；正确实现有`OrderContract.find`重写，不兼容必填实现没有该重写。旧批次绑定仍可解析，当前列表只显示新批次，最新Joern项目为closed。当前完整回归397项通过，2个警告为既有依赖弃用提示。

JavaScript/TypeScript静态CommonJS导入已解析：解构`require`等价命名导入，整模块`require`与`import * as`支持模块成员，默认导入只在目标模块存在唯一声明类型时解析，多个声明类型保持未知。默认导入的本地名不再要求等于导出类型名。两文件CommonJS合成仓库`secval-cjs-check-46055e9059034cb9a5982f90685a46eb`正式任务`d2cf7cbcef8d4018be56852a9a6eb619`、批次`28160e5f-1e6d-4069-b9e0-a31e8857e8e0`完成，5块/5向量、失败文件0；解构与整模块两种写法的调用都只连接完整类型`orders.OrderService.find`。当前完整回归400项通过，2个警告为既有依赖弃用提示。

更新时间：2026-09-06。本文是当前能力边界，不是完整能力验收报告。
最新本机核验：179项完整回归通过，1个既有依赖弃用警告。真实OpenSearch与SQLite快照取证检查通过。三类合成样例已取得核心supported/refuted/inconclusive结果：正例1条静态支持发现，反例及缺失依赖例无发现。评级、缺失依赖子问题判断及精确定位仍有不足，不能声明完整质量通过，详见根目录实施计划。没有外发用户真实仓库。最新API已重建部署，包括结果含义澄清、部分报告续跑、取消保护及2小时取证视图租约；健康检查和审计页面返回200。
模型单次请求超时使用`SECVAL_AUDIT_TIMEOUT_SECONDS`（代码默认120秒；用户批准后本机部署为300秒），输出上限使用`SECVAL_AUDIT_MAX_OUTPUT_TOKENS`（默认8192）。输出上限不是实际耗用量，也不能保证响应速度。中文JSON保持原文，恢复旧检查点时通过JSON解析重新序列化，不直接转义源码。主调查连续三次格式错误会停止，间隔成功动作的历史错误不触发连续错误保护。
正式HTTP链路已完成合成ZIP上传、生产索引（12块/12向量）和混合搜索验证；正式审计越过基线后遇到120秒请求超时，不能记为端到端审计完成。新增请求数值统计便于复查，完整状态与产物位置见根目录实施计划。可选`SECVAL_AUDIT_THINKING`默认为空；关闭思考探针被当前接口拒绝（HTTP400），没有默认启用该扩展。
历史部署记录：当时记录236项测试通过，健康检查及`/audit`返回200；当时未调用真实审计模型。该记录不是当前版本的验收结论。
后续实际取证验证：`benchmarks/recall_baseline/check_snapshot_evidence.py` 在真实 OpenSearch 与临时 SQLite 上通过。覆盖块/文件摘要一致、路径清单约束、精确行范围、配置授权、磁盘与实时索引变化后的固定视图，以及未绑定新批次拒绝读取。仅创建唯一测试索引并在结束后删除；不涉及已有仓库或真实模型。另补目录遍历失败时回滚快照，避免跳过无权限目录后误报采集成功。
## 目标与实现方式
参考用户提供的 Codex Security 0.1.25 方法，自建 Python Web 后端；不是移植其私有实现，也不依赖其插件运行。保持 API、services、models、interfaces、infrastructure 分层。审计以只读源码证据为基础，不执行被审计仓库代码。
## 已有主流程
1. 接受仓库、版本、可选路径范围、用户安全背景和威胁模型，检查远端源码授权。
2. 固定搜索视图；有精确索引批次绑定时，使用不可变源码快照。旧索引缺少绑定时明确报告限制。
3. 独立上下文先建立基线问题，再记录安全边界、威胁模型、调查问题及反证。
4. 通过搜索、符号查找、代码块和整文件读取获得带版本、位置与内容摘要的证据。支持可选起止行。
5. 登记调查结论与漏洞详情；独立上下文复核，可主动补读源码。复核不是不同模型，也不是动态验证。
6. 汇总候选、静态支持发现、反驳项、未决问题和覆盖限制，持久化任务并导出 JSON。
## 文件覆盖的新约束
字符阅读量与安全审阅声明分开保存。模型必须完整读取同一快照的文件后，才能登记检查过的控制、判断与未知项；读取零散代码块不能替代整文件阅读。
后端对照固定源码清单检查路径、快照 ID 和内容摘要，列出已声明静态审阅、尚未审阅与排除文件。有未知项的声明仍为部分审阅。模型声明不代表语义已被独立证实，更不代表项目没有漏洞；报告保持 `coverage.complete=false`。
配置正文只允许用户明确选定的配置路径并单独同意外发；不读取 `.env`。此限制不保证 Java 或其他获批文件里没有秘密。
## 尚未完成的验收项
新增报告`completion`字段：区分未提交、部分报告和已登记检查项收口；任何状态均不声称完整安全审计。部分报告有未完成项时，可显式授权从检查点建立子任务；父报告不修改，旧独立复核与发现不直接复用，快照/批次/范围约束继续生效。
真实反例暴露了状态含义歧义：模型将“支持防护有效”写为`supported`。现统一主调查与独立复核的说明：该字段只判断漏洞假设，支持防护有效应为`refuted`，决定性证据不足应为`inconclusive`。这是协议提示修正，不是自动语义证明；仍需真实反例复验，不能手工改历史标签来宣称通过。
随后真实反例续跑已将核心问题修正为refuted，旧错误状态仍保存在父任务与修订历史中。取证视图租约由10分钟改为2小时，任务结束主动释放；取证服务错误单独落盘，不回退实时索引。数据库原已冻结cancelled任务，本轮补运行层提前返回和回归测试，没有放宽冻结规则。
已补充主调查检查点及 `POST /api/audits/{id}/resume`：停止的任务在源码快照、索引批次、路径与配置授权、源码清单一致时，可显式授权启动新的续跑任务。父任务保持原样，报告记录父任务与前段模型调用次数。恢复的是最后已落盘的调查上下文与证据，不是重放过期连接或声称上次未返回的请求未计费。独立验证阶段中断时回到之前的主调查边界，后续重新验证。
基线阶段也逐次保存自己的上下文和阅读证据；中断后恢复基线，不混入主调查假设。请求发送前计数，网络失败的调用保留在父任务累计次数中；没有自动重试或保证上游未计费的承诺。
上下文达到 80000 字符时，基线和主调查会尝试确定性压缩较早工具消息中的源码正文：原始证据、审计判断、未知项、位置与引用保留，最近四条消息不压缩；省略项明确要求需要源码时重新读取。不是让模型生成摘要，也不删除持久化证据。检查点恢复时采用相同策略；压缩后仍超限则明确停止/拒绝续跑。大量调查记录本身超限的问题仍需要任务拆分解决。
调用预算可显式设置为 1–300 次，时长预算为 30–3600 秒；默认仍为 12 次、300 秒，不自动扩大调用费用。基线、主调查和独立验证共用本次额度，续跑建立新的显式预算并保留之前的调用计数。时长在请求边界检查，不能强制撤回已发送请求，也不是 token 或货币费用上限。API、领域校验、报告和测试前端采用相同参数。
主调查新增只读 `audit_progress(offset=0)`：从后端记录计算未审文件、未接续基线问题、未调查边界和待复核候选，每页20项，并提供剩余调用数。模型不能通过参数修改完成状态。没有源码清单时文件数量为未知，而不是零；待办清空也不代表所有真实入口已被发现或项目安全。
基线、主调查和独立验证支持 `search_source(text, offset=0)`：在精确绑定的源码快照中做大小写敏感字面搜索，搜索授权路径内的已支持源码（Java与Python，随解析器扩展自动覆盖）与明确批准的配置；每文件首个命中，每页20文件。结果为位置线索，不提供可直接引用的证据 ID，必须 `read_file` 读取核实。它不是正则搜索、LSP 或调用图，也不会回退到当前磁盘目录。扫描有界快照，未建立全文索引缓存，大项目重复查询仍有性能成本。

限制：无源码绑定、版本变化或上下文接近上限会拒绝续跑。当前仍不是自动无限调度或通用任意阶段恢复。测试前端已提供范围、配置授权、基线、调用上限和续跑入口。

- 带类型解析的更精确调用关系、Joern自定义语义、Java与Python之外的语言实测。
- 真实项目（非合成）Web链路验收；真实仓库外发需用户单独授权。
- 多进程协调、源码采集并发硬化；当前仅面向本机单用户，不适合直接公开部署。

不得把单元测试通过、模型返回报告或未发现漏洞描述为完整审计完成。真实合成验收仍在进行；不能据此声称与 Codex Security 等效。
