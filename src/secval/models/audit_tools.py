"""三个审计阶段共用的只读工具定义；不声明尚未接入的分析能力。"""

READ_TOOL_ARGUMENTS = {
    "list_chunks": {"offset"},
    "search_text": {"text", "offset"},
    "find_symbol": {"text", "offset"},
    "read_chunk": {"chunk_id", "char_offset", "start_line", "end_line"},
    "list_files": {"offset"},
    "read_file": {"path", "char_offset", "start_line", "end_line"},
    "search_source": {"text", "offset"},
    "hybrid_search": {"text", "top_k"},
    "find_code_relations": {"symbol", "limit"},
    "find_code_calls": {"method", "limit"},
    "find_data_paths": {"source_method", "sink_method", "limit"},
    "find_entry_points": {"framework", "limit"},
}

READ_TOOL_DESCRIPTIONS = {
    "list_chunks": "list_chunks(offset=0)：列出固定索引视图中的块，每页20条。",
    "search_text": "search_text(text,offset=0)：索引正文短语匹配，每页20条，不是字面或正则搜索。",
    "find_symbol": "find_symbol(text,offset=0)：完整符号签名精确匹配，每页20条，不是调用图。",
    "read_chunk": "read_chunk(chunk_id,char_offset=0)：读取固定索引代码块，每次最多12000字符。",
    "list_files": "list_files(offset=0)：列出绑定快照的采集清单及排除项，每页100项。",
    "read_file": "read_file(path,char_offset=0)：读取绑定快照中的已支持源码或明确批准的配置，每次最多12000字符。",
    "search_source": "search_source(text,offset=0)：绑定快照内区分大小写的字面搜索，每文件首个命中，每页20文件。",
    "hybrid_search": "hybrid_search(text,top_k=10)：部署提供该能力时，BM25与向量召回后用RRF合并，只返回固定视图中可验证的位置线索。",
    "find_code_relations": "find_code_relations(symbol,limit=20)：部署提供该能力时，在固定索引批次的Neo4j关系图中查找文件与符号的声明关系。",
    "find_code_calls": "find_code_calls(method,limit=20)：部署提供该能力时，在固定索引批次的Joern图中查找方法调用位置。",
    "find_data_paths": "find_data_paths(source_method,sink_method,limit=10)：查找源方法参数到目标调用参数的数据流位置。",
    "find_entry_points": "find_entry_points(framework='all',limit=50)：在固定源码快照中按已知Spring、JAX-RS、FastAPI/Flask或Django标记查找Web入口位置。",
}


def read_tool_prompt():
    """从同一份定义生成说明，减少基线、主调查与复核之间的偏差。"""
    lines = [READ_TOOL_DESCRIPTIONS[name] for name in READ_TOOL_ARGUMENTS]
    lines.append('一次只返回一个合法JSON对象，例如：{"tool":"list_files","arguments":{"offset":0}}。')
    lines.append("读取可选start_line/end_line（从1开始，两端包含），不能与char_offset混用；按行超12000字符须缩小范围。")
    lines.append("使用返回的next_offset或next_char_offset续读；只能引用读取返回的evidence_id，不自行拼写。")
    lines.append("搜索结果是线索，不是已读证据；源码阅读不等于完成安全审计。")
    lines.append("可用工具以scope_info.tools为准；hybrid_search不返回源码、也不调用外部重排序，命中后必须read_chunk或read_file取证。")
    lines.append("缺少绑定或配置授权时文件工具不可用，不得回退当前磁盘。Neo4j声明关系及Joern路径都是线索，必须读取源码核实。")
    return "\n".join(lines)
