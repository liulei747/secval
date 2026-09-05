import hashlib

from opensearchpy.exceptions import OpenSearchException

from secval.code_processing.repository_scan import is_supported_source
from secval.infrastructure.opensearch.code_index import CODE_INDEX_NAME
from secval.infrastructure.audit.framework_entry_finder import find_framework_entries
from secval.models.audit_scope import (
    in_scope,
    validate_config_paths,
    validate_scope_paths,
)
from secval.models.source_range import source_range, validate_line_range
from secval.models.audit_tools import READ_TOOL_ARGUMENTS
from secval.models.audit import EvidenceServiceError

# 覆盖最长60分钟任务及慢请求等待；正常结束会主动释放，不等租约到期。
VIEW_KEEP_ALIVE = "2h"


class EvidenceTools:
    def __init__(self, connection, repository_id, snapshot_id, source_store=None, *, index_name=None,
                 search_service=None, graph_store=None, joern_client=None):
        self.connection = connection
        # 默认仍使用正式索引；离线验收可明确指定独立测试索引。
        self.index_name = CODE_INDEX_NAME if index_name is None else index_name
        if not isinstance(self.index_name, str) or not self.index_name.strip():
            raise ValueError("取证索引名称不能为空")
        self.repository_id = repository_id
        self.snapshot_id = snapshot_id
        self.source_store = source_store
        self.search_service = search_service
        self.graph_store = graph_store
        self.joern_client = joern_client
        self.scope_paths = []
        self.approved_config_paths = []
        self.pit_id = None
        self.closed = False
        self.filters = [
            {"term": {"repository_id": repository_id}},
            {"term": {"snapshot_id": snapshot_id}},
        ]

    def close(self):
        self.closed = True
        if self.pit_id is not None:
            pit_id, self.pit_id = self.pit_id, None
            try:
                self.connection.transport.perform_request(
                    "DELETE", "/_search/point_in_time", body={"pit_id": [pit_id]}
                )
            except OpenSearchException:
                # 有限租约最终释放资源；清理失败不覆盖调查结果。
                pass

    def _open_view(self):
        if self.closed:
            raise RuntimeError("取证视图已经关闭")
        if self.pit_id is None:
            response = self.connection.transport.perform_request(
                "POST",
                f"/{self.index_name}/_search/point_in_time",
                params={"keep_alive": VIEW_KEEP_ALIVE, "allow_partial_pit_creation": "false"},
            )
            pit_id = response.get("pit_id")
            if not isinstance(pit_id, str) or not pit_id:
                raise RuntimeError("无法建立一致取证视图")
            self.pit_id = pit_id

    def call(self, name, arguments):
        try:
            return self._call(name, arguments)
        except OpenSearchException:
            raise EvidenceServiceError("固定取证视图或搜索服务不可用；没有切换实时索引") from None

    def _call(self, name, arguments):
        if name == "approve_config_files":
            if self.pit_id is not None or self.closed or self.approved_config_paths:
                raise ValueError("取证开始后不能改变配置授权")
            if not isinstance(arguments, dict) or set(arguments) != {"paths"}:
                raise ValueError("配置授权参数不合法")
            self.approved_config_paths = validate_config_paths(arguments["paths"], self.scope_paths)
            return {"approved_config_paths": self.approved_config_paths}
        if name == "restrict_scope":
            if self.pit_id is not None or self.closed or self.scope_paths:
                raise ValueError("取证开始后不能改变授权路径")
            if not isinstance(arguments, dict) or set(arguments) != {"paths"}:
                raise ValueError("范围参数不合法")
            paths = validate_scope_paths(arguments["paths"])
            if not paths:
                raise ValueError("限制路径不能为空")
            self.scope_paths = paths
            self.filters.append({"bool": {"minimum_should_match": 1, "should": [
                clause for path in paths for clause in (
                    {"term": {"relative_path": path}}, {"prefix": {"relative_path": path + "/"}},
                )
            ]}})
            return {"scope_paths": paths}
        if name == "scope_info":
            if arguments != {}:
                raise ValueError("scope_info不接受参数")
            chunks = self.call("list_chunks", {})
            scope = {"repository_id": self.repository_id, "snapshot_id": self.snapshot_id,
                     "scope_paths": self.scope_paths,
                     "approved_config_paths": self.approved_config_paths,
                     "indexed_chunks": chunks["total"], "view_id": chunks["view_id"],
                     "tools": ["list_chunks", "search_text", "find_symbol", "read_chunk"],
                     "source_snapshot_id": None,
                     "limitations": ["仅明确批准的配置正文可读，其他配置不可读", "没有LSP/调用图或动态执行能力",
                                     "搜索命中和源码阅读不等于完成安全审计"]}
            try:
                files = self._file_call("list_files", {})
            except ValueError as error:
                scope["limitations"].append(str(error))
            else:
                scope.update(source_snapshot_id=files["source_snapshot_id"], index_run_id=files["index_run_id"])
                scope["tools"].extend(["list_files", "read_file", "search_source", "find_entry_points"])
                inventory = []
                for offset in range(0, 10000, 100):
                    batch = self.source_store.inventory(files["source_snapshot_id"], offset)
                    inventory.extend(row for row in batch if in_scope(row["path"], self.scope_paths))
                    if len(batch) < 100:
                        break
                scope["inventory_entry_count"] = len(inventory)
                scope["_inventory"] = inventory
            if self.search_service is not None:
                scope["tools"].append("hybrid_search")
            if self.graph_store is not None:
                scope["tools"].append("find_code_relations")
                scope["limitations"] = [item for item in scope["limitations"]
                                        if "调用图" not in item]
                scope["limitations"].append("Neo4j当前只保存文件与符号的声明关系，不代表调用链")
            if self.joern_client is not None:
                scope["tools"].extend(["find_code_calls", "find_data_paths"])
                scope["limitations"].append("Joern调用和数据流结果是静态分析线索，可能存在漏报或误报")
            return scope
        if name == "hybrid_search":
            from secval.models.audit_contracts import ToolAction
            ToolAction.parse({"tool": name, "arguments": arguments})
            return self._hybrid_search(arguments)
        if name == "find_code_relations":
            from secval.models.audit_contracts import ToolAction
            ToolAction.parse({"tool": name, "arguments": arguments})
            if self.graph_store is None:
                raise ValueError("当前未配置代码关系存储")
            bound = self._file_call("list_files", {})
            rows = self.graph_store.find_symbol(
                self.repository_id, self.snapshot_id, bound["index_run_id"],
                arguments["symbol"], arguments.get("limit", 20),
            )
            rows = [row for row in rows if in_scope(row.get("path", ""), self.scope_paths)]
            return {"rows": rows, "view_id": bound["view_id"],
                    "index_run_id": bound["index_run_id"],
                    "relation_note": "只表示文件DECLARES符号；是定位线索，必须read_file或read_chunk后才能成为证据"}
        if name == "find_code_calls":
            from secval.models.audit_contracts import ToolAction
            ToolAction.parse({"tool": name, "arguments": arguments})
            if self.joern_client is None:
                raise ValueError("当前未配置Joern代码路径服务")
            bound = self._file_call("list_files", {})
            raw_rows = self.joern_client.find_calls(
                bound["index_run_id"], arguments["method"], arguments.get("limit", 20)
            )
            captured_paths = self._captured_paths(bound["source_snapshot_id"])
            rows = []
            for row in raw_rows:
                path = self._match_joern_path(row.get("path", ""), captured_paths)
                if path is None or not in_scope(path, self.scope_paths):
                    continue
                rows.append({**row, "path": path})
            return {"rows": rows, "view_id": bound["view_id"],
                    "index_run_id": bound["index_run_id"],
                    "path_note": "Joern调用位置只是路径分析线索；必须read_file核实源码后才能作为证据"}
        if name == "find_data_paths":
            from secval.models.audit_contracts import ToolAction
            ToolAction.parse({"tool": name, "arguments": arguments})
            if self.joern_client is None:
                raise ValueError("当前未配置Joern代码路径服务")
            bound = self._file_call("list_files", {})
            raw_paths = self.joern_client.find_data_paths(
                bound["index_run_id"], arguments["source_method"], arguments["sink_method"],
                arguments.get("limit", 10),
            )
            captured_paths = self._captured_paths(bound["source_snapshot_id"])
            paths = []
            for raw_path in raw_paths:
                steps = []
                for step in raw_path["steps"]:
                    path = self._match_joern_path(step.get("path", ""), captured_paths)
                    if path is None or not in_scope(path, self.scope_paths):
                        steps = []
                        break
                    steps.append({**step, "path": path})
                if steps:
                    paths.append({"steps": steps})
            return {"paths": paths, "view_id": bound["view_id"],
                    "index_run_id": bound["index_run_id"],
                    "path_note": "静态数据流是待核实线索；路径中的相关源码必须read_file后才能引用"}
        if name == "find_entry_points":
            from secval.models.audit_contracts import ToolAction
            ToolAction.parse({"tool": name, "arguments": arguments})
            bound = self._file_call("list_files", {})
            rows = find_framework_entries(
                self.source_store, bound["source_snapshot_id"], self.scope_paths,
                arguments.get("framework", "all"), arguments.get("limit", 50),
            )
            return {"rows": rows, "view_id": bound["view_id"],
                    "index_run_id": bound["index_run_id"],
                    "entry_note": "框架标记只是入口位置线索；必须read_file核实路由、参数和权限控制"}
        if name in ("list_files", "read_file", "search_source"):
            from secval.models.audit_contracts import ToolAction
            ToolAction.parse({"tool": name, "arguments": arguments})
            return self._file_call(name, arguments)
        if not isinstance(arguments, dict):
            raise ValueError("工具参数必须是对象")
        allowed = READ_TOOL_ARGUMENTS
        if name not in allowed or set(arguments) - allowed[name]:
            raise ValueError("工具或参数不允许")
        validate_line_range(arguments)
        offset = arguments.get("offset", 0)
        if type(offset) is not int or not 0 <= offset <= 9980:
            raise ValueError("offset必须是0到9980的整数")
        filters = list(self.filters)
        must = []
        char_offset = arguments.get("char_offset", 0)
        if type(char_offset) is not int or char_offset < 0:
            raise ValueError("char_offset必须为非负整数")
        if name in ("search_text", "find_symbol"):
            text = arguments.get("text")
            if not isinstance(text, str) or not 1 <= len(text) <= 500:
                raise ValueError("text必须为1到500字符")
            if name == "find_symbol":
                filters.append({"term": {"symbol_names.exact": text}})
            else:
                must.append({"match_phrase": {"content": text}})
        if name == "read_chunk":
            chunk_id = arguments.get("chunk_id")
            if not isinstance(chunk_id, str) or not 1 <= len(chunk_id) <= 200:
                raise ValueError("chunk_id不合法")
            filters.append({"term": {"chunk_id": chunk_id}})
        body = {
            "query": {"bool": {"filter": filters, "must": must}},
            "from": offset,
            "size": 1 if name == "read_chunk" else 20,
            "track_total_hits": True,
            "sort": [{"chunk_id": "asc"}],
        }
        self._open_view()
        body["pit"] = {"id": self.pit_id, "keep_alive": VIEW_KEEP_ALIVE}
        if name != "read_chunk":
            body["_source"] = {"excludes": ["content", "search_text"]}
        # PIT失效或请求失败时不退回实时索引，避免悄悄混用版本。
        response = self.connection.search(body=body)
        if response.get("timed_out") or response.get("_shards", {}).get("failed", 0):
            raise RuntimeError("取证查询不完整，停止调查")
        total = response["hits"]["total"]["value"]
        rows = []
        for hit in response["hits"]["hits"]:
            source = hit["_source"]
            if not in_scope(source.get("relative_path", ""), self.scope_paths):
                raise RuntimeError("索引返回范围外内容，停止调查")
            row = {
                k: source.get(k)
                for k in (
                    "chunk_id",
                    "repository_id",
                    "snapshot_id",
                    "index_run_id",
                    "relative_path",
                    "symbol_name",
                    "start_line",
                    "end_line",
                )
            }
            if name == "read_chunk":
                content = source["content"]
                char_offset, end_offset, line_mode = source_range(content, arguments, source["start_line"])
                fragment = content[char_offset:end_offset]
                start_line = source["start_line"] + content[:char_offset].count("\n")
                digest = hashlib.sha256(content.encode()).hexdigest()
                row.update(
                    content=fragment,
                    truncated=char_offset > 0 or end_offset < len(content),
                    content_sha256=digest,
                    evidence_id=(
                        source["chunk_id"]
                        if char_offset == 0 and end_offset == len(content)
                        else f"{source['chunk_id']}:{digest[:12]}:{char_offset}:{end_offset}"
                    ),
                    char_offset=char_offset,
                    end_char_offset=end_offset,
                    next_char_offset=end_offset if not line_mode and end_offset < len(content) else None,
                    total_characters=len(content),
                    chunk_start_line=source["start_line"],
                    chunk_end_line=source["end_line"],
                    start_line=start_line,
                    end_line=start_line + fragment.removesuffix("\n").count("\n"),
                )
            rows.append(row)
        return {
            "rows": rows,
            "total": total,
            "next_offset": offset + len(rows) if offset + len(rows) < total else None,
            "view_id": hashlib.sha256(self.pit_id.encode()).hexdigest(),
            "scope_note": "任务开始时的索引PIT视图；不是完整源码清单或可持久恢复的仓库快照",
        }

    def _hybrid_search(self, arguments):
        """实时混合召回只负责找线索；返回前必须通过本任务固定PIT和批次校验。"""
        if self.search_service is None:
            raise ValueError("当前未配置混合搜索服务")
        # 先打开视图，保证之后发生的重建不会混进本次审计结果。
        bound = self._file_call("list_files", {})
        from secval.models.identifiers import RepositoryId, SnapshotId
        from secval.models.search import SearchQuery
        query = SearchQuery(text=arguments["text"], repository_ids=[RepositoryId(self.repository_id)],
                            snapshot_ids=[SnapshotId(self.snapshot_id)], top_k=100)
        keyword = self.search_service.keyword_retriever.search(query)
        vector = self.search_service.vector_retriever.search(query)
        candidates = self.search_service.result_fusion.fuse(keyword, vector, top_k=100)
        candidate_ids = [str(item.chunk.chunk_id) for item in candidates]
        if not candidate_ids:
            return {"rows": [], "view_id": bound["view_id"], "search_note":
                    "混合搜索只提供线索；没有命中；未调用外部重排序"}
        response = self.connection.search(body={
            "size": len(candidate_ids),
            "query": {"bool": {"filter": [*self.filters, {"terms": {"chunk_id": candidate_ids}}]}},
            "pit": {"id": self.pit_id, "keep_alive": VIEW_KEEP_ALIVE},
            "_source": {"excludes": ["content", "search_text"]},
        })
        if response.get("timed_out") or response.get("_shards", {}).get("failed", 0):
            raise RuntimeError("混合搜索固定视图校验不完整，停止调查")
        visible = {hit["_source"]["chunk_id"]: hit["_source"] for hit in response["hits"]["hits"]}
        rows = []
        wanted = arguments.get("top_k", 10)
        for item in candidates:
            source = visible.get(str(item.chunk.chunk_id))
            if source is None or source.get("index_run_id") != bound["index_run_id"]:
                continue
            path = source.get("relative_path", "")
            if not in_scope(path, self.scope_paths):
                continue
            rows.append({"chunk_id": source["chunk_id"], "relative_path": path,
                         "symbol_name": source.get("symbol_name"), "start_line": source.get("start_line"),
                         "end_line": source.get("end_line"), "rank": len(rows) + 1,
                         "rrf_score": item.rrf_score, "keyword_score": item.keyword_score,
                         "vector_score": item.vector_score})
            if len(rows) == wanted:
                break
        return {"rows": rows, "view_id": bound["view_id"], "index_run_id": bound["index_run_id"],
                "search_note": "BM25与向量结果经RRF合并；仅是线索，未返回源码、未调用外部重排序；必须读取后才能引用"}

    def _captured_paths(self, source_snapshot_id):
        inventory = []
        for offset in range(0, 10000, 100):
            batch = self.source_store.inventory(source_snapshot_id, offset)
            inventory.extend(batch)
            if len(batch) < 100:
                break
        return [row["path"] for row in inventory if row["status"] == "captured"]

    @staticmethod
    def _match_joern_path(joern_path, captured_paths):
        normalized = joern_path.replace("\\", "/")
        matches = [path for path in captured_paths
                   if normalized == path or normalized.endswith("/" + path)]
        return matches[0] if len(matches) == 1 else None

    def _file_call(self, name, arguments):
        self._open_view()
        if self.source_store is None:
            raise ValueError("当前未配置源码快照存储")
        response = self.connection.search(body={
            "size": 0, "query": {"bool": {"filter": self.filters}},
            "pit": {"id": self.pit_id, "keep_alive": VIEW_KEEP_ALIVE},
            "aggs": {
                "runs": {"terms": {"field": "index_run_id", "size": 2}},
                "missing_run": {"missing": {"field": "index_run_id"}},
            },
        })
        if response.get("timed_out") or response.get("_shards", {}).get("failed", 0):
            raise RuntimeError("批次查询不完整，停止调查")
        aggregates = response["aggregations"]
        runs = aggregates["runs"]["buckets"]
        if len(runs) != 1 or aggregates["missing_run"]["doc_count"]:
            raise ValueError("当前视图没有唯一完整批次，文件取证不可用")
        run = runs[0]["key"]
        source_id = self.source_store.resolve_binding(self.repository_id, self.snapshot_id, run)
        if source_id is None:
            raise ValueError("该索引批次没有源码快照绑定，不能使用当前磁盘源码代替")
        result = {
            "view_id": hashlib.sha256(self.pit_id.encode()).hexdigest(),
            "source_snapshot_id": source_id, "index_run_id": run,
            "scope_note": "采集快照；排除项不代表已审计。仅开放已支持源码及用户明确批准的配置正文。",
        }
        if name == "search_source":
            result.update(self._search_source(source_id, arguments))
            return result
        if name == "list_files":
            offset = arguments.get("offset", 0)
            if self.scope_paths:
                all_rows = []
                for page in range(0, 10000, 100):
                    batch = self.source_store.inventory(source_id, page)
                    all_rows.extend(row for row in batch if in_scope(row["path"], self.scope_paths))
                    if len(batch) < 100:
                        break
                rows = all_rows[offset:offset + 100]
                next_offset = offset + len(rows) if offset + len(rows) < len(all_rows) else None
            else:
                rows = self.source_store.inventory(source_id, offset)
                next_offset = offset + len(rows) if len(rows) == 100 and offset + len(rows) < 10000 else None
            result.update(rows=rows, next_offset=next_offset)
            return result
        path = arguments["path"]
        if not in_scope(path, self.scope_paths):
            raise ValueError("文件不在任务授权路径内")
        if not is_supported_source(path) and path not in self.approved_config_paths:
            raise ValueError("仅允许已支持源码及任务明确批准的配置文件正文")
        content = self.source_store.read(source_id, path)
        offset, end, line_mode = source_range(content, arguments)
        fragment = content[offset:end]
        digest = hashlib.sha256(content.encode()).hexdigest()
        file_id = "file:" + hashlib.sha256(f"{source_id}:{path}".encode()).hexdigest()
        start_line = 1 + content[:offset].count("\n")
        result["rows"] = [{
            "chunk_id": file_id, "evidence_id": f"{file_id}:{offset}:{end}",
            "repository_id": self.repository_id, "snapshot_id": self.snapshot_id,
            "source_snapshot_id": source_id, "index_run_id": run,
            "relative_path": path, "content": fragment, "content_sha256": digest,
            "start_line": start_line,
            "end_line": start_line + fragment.removesuffix("\n").count("\n"),
            "truncated": offset > 0 or end < len(content),
            "char_offset": offset, "next_char_offset": end if not line_mode and end < len(content) else None,
            "total_characters": len(content),
        }]
        return result

    def _search_source(self, source_id, arguments):
        """大小写敏感字面匹配，每文件仅返回首个位置；不把搜索当作已读证据。"""
        offset = arguments.get("offset", 0)
        text = arguments["text"]
        hits = []
        matched = 0
        for page in range(0, 10000, 100):
            rows = self.source_store.inventory(source_id, page)
            for row in rows:
                path = row["path"]
                if (row["status"] != "captured" or not in_scope(path, self.scope_paths)
                        or (not is_supported_source(path) and path not in self.approved_config_paths)):
                    continue
                content = self.source_store.read(source_id, path)
                position = content.find(text)
                if position < 0:
                    continue
                matched += 1
                if matched <= offset:
                    continue
                hits.append({"path": path, "char_offset": position,
                             "start_line": 1 + content[:position].count("\n"),
                             "end_line": 1 + content[:position].count("\n") + text.removesuffix("\n").count("\n"),
                             "content_sha256": row["digest"]})
                if len(hits) == 21:
                    return {"rows": hits[:20], "next_offset": offset + 20,
                            "search_note": "字面且区分大小写；每文件首个命中；必须read_file核实后才能引用"}
            if len(rows) < 100:
                break
        return {"rows": hits, "next_offset": None,
                "search_note": "字面且区分大小写；每文件首个命中；必须read_file核实后才能引用"}
