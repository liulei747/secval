"""三个审计阶段共用的只读工具定义；不声明尚未接入的分析能力。"""

# [SECVAL-OVERFIT-6] 审计面向模型暴露的工具集从 14 个收敛到 3 个核心工具。
# 依据：对比 Codex Security 的做法——它只给模型一个离线搜索命令加整文件读取，
# 靠"读完整源码 + 明确的漏洞类别清单"达到高召回，而不是靠大量窄接口。
# 原设计里模型要把有限推理预算花在"该调哪个工具"上，且每次只拿到片段，
# 无法看到完整控制流（例如"这个方法虽被调用，但调用点在 if (!isAdmin) 内"）。
#
# 保留：search_source（字面搜索）、read_file（整文件）、list_files（清单）
# 其余工具仍在本文件登记参数与说明，供验证管线、图页面与人工核查使用，
# 但不再进入模型的工具目录。恢复方式：把它们加回 AUDIT_MODEL_TOOLS。
CORE_TOOLS = ("search_source", "read_file", "list_files")

# 模型审计目录：只暴露核心三件套。
AUDIT_MODEL_TOOLS = CORE_TOOLS

# 非模型工具：供 path_validation_pipeline、图页面、人工核查使用。
ANALYSIS_ONLY_TOOLS = (
    "batch_evidence", "list_chunks", "search_text", "find_symbol", "read_chunk",
    "hybrid_search", "find_code_relations", "find_code_callers", "find_code_callees",
    "find_code_type_relations", "find_dispatch_targets", "find_code_calls",
    "find_data_paths", "find_entry_points",
)

READ_TOOL_ARGUMENTS = {
    "batch_evidence": {"operations"},
    "list_chunks": {"offset"},
    "search_text": {"text", "offset"},
    "find_symbol": {"text", "offset"},
    "read_chunk": {"chunk_id", "char_offset", "start_line", "end_line"},
    "list_files": {"offset"},
    "read_file": {"path", "char_offset", "start_line", "end_line"},
    "search_source": {"text", "offset"},
    "hybrid_search": {"text", "top_k"},
    "find_code_relations": {"symbol", "limit"},
    "find_code_callers": {"symbol", "limit"},
    "find_code_callees": {"symbol", "limit"},
    "find_code_type_relations": {"symbol", "limit"},
    "find_dispatch_targets": {"symbol", "limit", "receiver_type"},
    "find_code_calls": {"method", "limit"},
    "find_data_paths": {"source_method", "sink_method", "limit"},
    "find_entry_points": {"framework", "limit"},
}

READ_TOOL_DESCRIPTIONS = {
    "batch_evidence": "batch_evidence(operations)：一次执行最多12个独立只读取证动作；每项为{tool,arguments}，可批量read_file/read_chunk/search_source/hybrid_search及符号、调用、数据流和入口查询。禁止嵌套batch_evidence；逐项返回结果或错误，源码总正文最多36000字符。",
    "list_chunks": "list_chunks(offset=0)：列出固定索引视图中的块，每页20条。",
    "search_text": "search_text(text,offset=0)：索引正文短语匹配，每页20条，不是字面或正则搜索。",
    "find_symbol": "find_symbol(text,offset=0)：完整符号签名精确匹配，每页20条，不是调用图。",
    "read_chunk": "read_chunk(chunk_id,char_offset=0)：读取固定索引代码块，每次最多12000字符。",
    "list_files": "list_files(offset=0)：列出绑定快照的采集清单及排除项，每页100项。",
    "read_file": "read_file(path,char_offset=0)：读取绑定快照中的已支持源码或明确批准的配置，每次最多12000字符。",
    "search_source": "search_source(text,offset=0)：绑定快照内区分大小写的字面搜索，每文件首个命中，每页20文件。",
    "hybrid_search": "hybrid_search(text,top_k=10)：部署提供该能力时，BM25与向量召回后用RRF合并，只返回固定视图中可验证的位置线索。",
    "find_code_relations": "find_code_relations(symbol,limit=20)：部署提供该能力时，在固定索引批次的Neo4j关系图中查找文件与符号的声明关系。",
    "find_code_callers": "find_code_callers(symbol,limit=20)：返回调用者候选；查看每条match_basis和match_note，name_only仅为同名线索，不能确认调用链；类型匹配仍须读取源码核实。",
    "find_code_callees": "find_code_callees(symbol,limit=20)：返回被调用目标候选；查看每条match_basis和match_note，name_only仅为同名线索，不能确认调用链；类型匹配仍须读取源码核实。",
    "find_code_type_relations": "find_code_type_relations(symbol,limit=20)：返回仓库内已解析类型的继承、实现和覆盖关系；未解析的外部类型不生成边。",
    "find_dispatch_targets": "find_dispatch_targets(symbol,limit=20,receiver_type=None)：返回同名方法的仓库内覆盖实现候选；提供receiver_type时按调用点类型及祖先过滤，解析失败返回空。动态分派结果必须读取源码核实。",
    "find_code_calls": "find_code_calls(method,limit=20)：部署提供该能力时，在固定索引批次的Joern图中查找方法调用位置。",
    "find_data_paths": "find_data_paths(source_method,sink_method,limit=10)：查找源方法参数到目标调用参数的数据流位置。",
    "find_entry_points": "find_entry_points(framework='all',limit=50)：在固定源码快照中查找入口：Spring注解与函数式路由、@Bean/@EventListener/@KafkaListener/@RabbitListener/@Scheduled、JAX-RS、FastAPI/Flask（含程序式注册、APIRouter/Blueprint声明与挂载）、Django、JavaScript Express/Koa以及TypeScript NestJS；同时返回security_boundary类别的过滤器/拦截器/中间件（Java：@WebFilter/implements Filter/OncePerRequestFilter/HandlerInterceptor；Python：add_middleware、@app.middleware、*Middleware类；JavaScript：app.use/router.use线索；NestJS：@UseGuards/NestMiddleware）与authorization类别的方法级授权注解/装饰器（Java：@PreAuthorize/@Secured/@RolesAllowed/@SaCheck*/@Requires*等；Python：login_required/@authorize等），核对有效授权策略时应检查这些边界而不只看路由；authorization结果只说明注解存在，不保证策略生效，必须read_file核实表达式与注册方式。cross_language_process类别（Java：ProcessBuilder/Runtime.exec；Python：subprocess.run/Popen/os.system等；Node：child_process exec/spawn/execFile及同步版本）标记通过子进程调用另一语言可执行文件的跨语言边界，是命令注入跨语言传播的候选路径，必须read_file核实完整命令构造与输入来源。",
}


def iter_evidence_rows(tool_name, result):
    """Yield read results from a single operation or the bounded batch wrapper."""
    if not isinstance(result, dict):
        return
    if tool_name == "batch_evidence":
        for item in result.get("items", []):
            if isinstance(item, dict) and isinstance(item.get("result"), dict):
                yield from iter_evidence_rows(item.get("tool"), item["result"])
        return
    if tool_name in {"read_file", "read_chunk"}:
        yield from result.get("rows", [])


def read_tool_prompt():
    """从同一份定义生成说明，减少基线、主调查与复核之间的偏差。

    [SECVAL-OVERFIT-6] 只描述模型实际可用的核心工具。图与路径工具仍保留在
    READ_TOOL_ARGUMENTS 中供验证管线内部使用，但不再写进模型提示词——
    提示词里出现但不可调用的工具会误导模型，并诱导它依赖线索代替源码。
    """
    lines = [READ_TOOL_DESCRIPTIONS[name] for name in AUDIT_MODEL_TOOLS]
    lines.append("读取可选start_line/end_line（从1开始，两端包含），按行超12000字符须缩小范围。")
    lines.append("使用返回的next_offset或next_char_offset续读；只能引用读取返回的evidence_id，不自行拼写。")
    lines.append("搜索结果是线索，不是已读证据；源码阅读不等于完成安全审计。")
    lines.append("必须完整读取文件后再判断结论；只搜索到片段不构成已审阅。")
    lines.append("缺少绑定或配置授权时文件工具不可用，不得回退当前磁盘。")
    lines.append("危险操作的识别依据是你所读到的仓库实际代码与该仓库的威胁模型，"
                 "不依赖任何外部提供的危险函数清单。")
    return "\n".join(lines)
