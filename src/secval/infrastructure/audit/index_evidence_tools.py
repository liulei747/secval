import hashlib

from opensearchpy.exceptions import OpenSearchException

from secval.infrastructure.opensearch.code_index import CODE_INDEX_NAME
from secval.models.audit_scope import (
    in_scope,
    validate_config_paths,
    validate_scope_paths,
)
from secval.models.source_range import source_range, validate_line_range


class EvidenceTools:
    def __init__(self, connection, repository_id, snapshot_id, source_store=None):
        self.connection = connection
        self.repository_id = repository_id
        self.snapshot_id = snapshot_id
        self.source_store = source_store
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
                f"/{CODE_INDEX_NAME}/_search/point_in_time",
                params={"keep_alive": "10m", "allow_partial_pit_creation": "false"},
            )
            pit_id = response.get("pit_id")
            if not isinstance(pit_id, str) or not pit_id:
                raise RuntimeError("无法建立一致取证视图")
            self.pit_id = pit_id

    def call(self, name, arguments):
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
                scope["tools"].extend(["list_files", "read_file", "search_source"])
                inventory = []
                for offset in range(0, 10000, 100):
                    batch = self.source_store.inventory(files["source_snapshot_id"], offset)
                    inventory.extend(row for row in batch if in_scope(row["path"], self.scope_paths))
                    if len(batch) < 100:
                        break
                scope["inventory_entry_count"] = len(inventory)
                scope["_inventory"] = inventory
            return scope
        if name in ("list_files", "read_file", "search_source"):
            from secval.models.audit_contracts import ToolAction
            ToolAction.parse({"tool": name, "arguments": arguments})
            return self._file_call(name, arguments)
        if not isinstance(arguments, dict):
            raise ValueError("工具参数必须是对象")
        allowed = {
            "list_chunks": {"offset"},
            "search_text": {"text", "offset"},
            "find_symbol": {"text", "offset"},
            "read_chunk": {"chunk_id", "char_offset", "start_line", "end_line"},
        }
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
        body["pit"] = {"id": self.pit_id, "keep_alive": "10m"}
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

    def _file_call(self, name, arguments):
        self._open_view()
        if self.source_store is None:
            raise ValueError("当前未配置源码快照存储")
        response = self.connection.search(body={
            "size": 0, "query": {"bool": {"filter": self.filters}},
            "pit": {"id": self.pit_id, "keep_alive": "10m"},
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
            "scope_note": "采集快照；排除项不代表已审计。仅开放Java及用户明确批准的配置正文。",
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
        if not path.lower().endswith(".java") and path not in self.approved_config_paths:
            raise ValueError("仅允许Java源码及任务明确批准的配置文件正文")
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
                        or (not path.lower().endswith(".java") and path not in self.approved_config_paths)):
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
