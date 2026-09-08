"""Deterministic grouping between one-shot path discovery and validation."""

import hashlib
import json
import re

from secval.models.agent_work import parse_worker_finding, require_refs, require_strings, require_text
from secval.models.audit_contracts import ModelOutputError, ModelRequestError
from secval.services.audit_stages import record_stage


def build_validation_packets(sketches, *, max_paths=6):
    """Group shared roots/sinks so validation does not become one agent per path."""
    groups = {}
    for sketch in sketches:
        if sketch.get("status") not in {None, "queued_for_validation"}:
            continue
        # Sink prose varies per route even when paths share one vulnerability
        # family. Grouping on the prose created one model request per path and
        # defeated batch validation. The packet still carries every concrete
        # sink/path; surface + type is the stable batching boundary.
        key = (sketch["surface"], sketch["candidate_type"])
        groups.setdefault(key, []).append(sketch)
    packets = []
    for key in sorted(groups):
        rows = groups[key]
        for offset in range(0, len(rows), max_paths):
            batch = rows[offset:offset + max_paths]
            identity = json.dumps([row["id"] for row in batch], separators=(",", ":"))
            packets.append({
                "id": "validation:" + hashlib.sha256(identity.encode()).hexdigest()[:16],
                "surface": key[0], "candidate_type": key[1], "sink_key": "multiple",
                "path_ids": [row["id"] for row in batch],
                "evidence_ids": list(dict.fromkeys(ref for row in batch for ref in row["evidence_ids"])),
                "needs": _dedupe_needs(item for row in batch for item in row["needs"]),
                "status": "queued", "attempts": 0,
            })
    return packets


def _key(value):
    return " ".join(value.lower().split())[:200]


def _dedupe_needs(needs):
    seen, result = set(), []
    for need in needs:
        key = json.dumps(need, ensure_ascii=False, sort_keys=True)
        if key not in seen:
            seen.add(key)
            result.append(need)
    return result


def _need_operations(need):
    kind, target = need["kind"], need["target"]
    if kind == "file_read":
        if any(mark in target for mark in ("*", "classpath:")):
            filename = re.findall(r"[A-Za-z_$][A-Za-z0-9_$]*Mapper|\$\{", target)
            terms = filename or (["${"] if ".xml" in target else [])
            return [{"tool": "search_source", "arguments": {"text": term, "offset": 0}}
                    for term in terms[:4]]
        return [{"tool": "read_file", "arguments": {"path": target}}]
    if kind == "data_path" and "->" in target:
        source, sink = (part.strip() for part in target.split("->", 1))
        return [{"tool": "find_data_paths", "arguments":
                 {"source_method": source, "sink_method": sink, "limit": 10}}]
    relation = {"callers": "find_code_callers", "callees": "find_code_callees"}.get(kind)
    if relation:
        identifiers = [value for value in re.findall(r"[A-Za-z_$][A-Za-z0-9_$]*", target)
                       if value not in {"com", "org", "src", "main", "java", "service"}]
        owner = next((value for value in identifiers if any(ch.isupper() for ch in value)), None)
        member = identifiers[-1] if identifiers else target
        operations = [{"tool": relation, "arguments": {"symbol": member, "limit": 20}}]
        if owner:
            operations.append({"tool": "find_symbol", "arguments": {"text": owner, "offset": 0}})
        operations.extend([
            {"tool": "find_symbol", "arguments": {"text": member, "offset": 0}},
            {"tool": "search_source", "arguments": {"text": member, "offset": 0}},
        ])
        return operations[:4]
    terms = [target]
    if kind == "symbol_definition":
        # Fully-qualified targets make package fragments such as ``com`` and
        # ``service`` dominate a bounded batch. Resolve the method and class
        # exactly first so the validation packet receives the implementation,
        # not a dozen unrelated callers from the same package.
        # A need may name one fully qualified member or a compact group such as
        # ``DocumentService.loadDocument/storeDocument``. Extract every
        # class/method-shaped identifier and ignore generic package fragments.
        tokens = re.findall(r"[A-Za-z_$][A-Za-z0-9_$]*", target)
        identifiers = list(dict.fromkeys(
            value for index, value in enumerate(tokens)
            if any(character.isupper() for character in value)
            or (index and any(character.isupper() for character in tokens[index - 1]))
        ))
        operations = [{"tool": "find_symbol", "arguments": {"text": value, "offset": 0}}
                      for value in identifiers]
        operations.extend({"tool": "search_source", "arguments": {"text": value, "offset": 0}}
                          for value in identifiers)
        return operations[:4]
    elif kind == "config_lookup":
        path = next((value for value in re.findall(r"[A-Za-z0-9_./-]+\.(?:ya?ml|properties|json|xml)", target)
                     if "/" in value), None)
        if path:
            return [{"tool": "read_file", "arguments": {"path": path}}]
    elif kind == "route_guard":
        terms.extend(["RequiresPermissions", "filterChainDefinitions"])
    elif kind == "template_resolution":
        terms.extend(["ViewResolver", "prefix", "suffix"])
    if kind == "source_search":
        code_terms = re.findall(r"\$\{[^}]+\}|[A-Za-z_$][A-Za-z0-9_$.]{3,}", target)
        generic = {"src", "main", "resources", "java", "com", "service", "用法", "相关"}
        useful = [term for term in code_terms if term.lower() not in generic]
        terms = useful or terms
    return [{"tool": "search_source", "arguments": {"text": term, "offset": 0}}
            for term in dict.fromkeys(terms) if term][:4]


_DEPENDENCY_STOPWORDS = {
    "String", "Object", "Map", "List", "Set", "Integer", "Long", "Boolean",
    "Override", "Autowired", "RequestBody", "RequestParam", "PathVariable",
    "GetMapping", "PostMapping", "PutMapping", "PatchMapping", "DeleteMapping",
    "RequestMapping", "RestController", "Service", "Repository", "Component",
}


def _dependency_terms(packet, evidence):
    """Return bounded project symbols that can close source/control/sink gaps.

    This is deliberately a high-recall lexical frontier rather than a claim that
    the relation exists. Search results remain locators and are read before use.
    """
    terms = []
    for row in evidence.values():
        content = row.get("content", "")
        for qualified, name in re.findall(
                r"(?m)^\s*import\s+((?:[A-Za-z_$][\w$]*\.)+([A-Z][\w$]*));", content):
            if not qualified.startswith(("java.", "javax.", "jakarta.", "org.springframework.")):
                terms.append(name)
        terms.extend(re.findall(
            r"(?:private|protected|public)\s+([A-Z][A-Za-z0-9_$]*(?:DAO|Dto|DTO|Service|Repository|Mapper|Validator|Factory|Handler|Filter))\b",
            content,
        ))
    for sketch in packet.get("sketches", []):
        text = " ".join([sketch.get("source", ""), sketch.get("sink", ""),
                         sketch.get("control", ""), *sketch.get("hops", [])])
        terms.extend(re.findall(r"\b[A-Za-z_$][A-Za-z0-9_$]{3,}\b", text))
        # Follow only wrappers that invoke a symbol already on this candidate
        # path. This closes private-sink -> public-wrapper chains without the
        # broad all-method fanout that previously polluted packets.
        hop_symbols = re.findall(r"\b[A-Za-z_$][A-Za-z0-9_$]{3,}\b",
                                 " ".join(sketch.get("hops", [])))
        for row in evidence.values():
            content = row.get("content", "")
            for symbol in hop_symbols:
                for call in re.finditer(r"\b" + re.escape(symbol) + r"\s*\(", content):
                    declarations = re.findall(
                        r"(?:public|protected|private)\s+(?:[\w<>?,.\[\]]+\s+)+([A-Za-z_$][\w$]*)\s*\([^;{}]*\)\s*(?:throws[^{}]+)?\{",
                        content[:call.start()],
                    )
                    if declarations and declarations[-1] != symbol:
                        terms.append(declarations[-1])
    generic = _DEPENDENCY_STOPWORDS | {
        "return", "public", "private", "protected", "static", "throws", "catch",
        "super", "this", "value", "content", "request", "response", "build", "save",
    }
    seen, result = set(), []
    for term in terms:
        if term in generic or term.lower() in {item.lower() for item in generic}:
            continue
        if term not in seen:
            seen.add(term)
            result.append(term)
    return result[:24]


def _paths_from_tool_result(result):
    paths = []
    for item in result.get("items", []):
        child = item.get("result", {})
        for row in child.get("rows", []):
            path = row.get("path") or row.get("relative_path") or row.get("caller_path")
            if path and path not in paths:
                paths.append(path)
        for path_result in child.get("paths", []):
            for step in path_result.get("steps", []):
                if step.get("path") and step["path"] not in paths:
                    paths.append(step["path"])
    return paths


def supplement_packet_evidence(team, packet, base_evidence):
    """Build a bounded evidence closure from declared gaps and source relations."""
    declared = []
    for need in packet.get("needs", []):
        declared.extend(_need_operations(need))
    evidence = dict(base_evidence)
    searched, read_paths = set(), {row.get("relative_path") for row in evidence.values()}
    total_operations, stagnant, rounds = 0, 0, 0
    locator_results, read_results = [], []
    for round_number in range(1, 4):
        rounds = round_number
        operations = []
        if round_number == 1:
            operations.extend(declared)
        frontier_terms = []
        for term in _dependency_terms(packet, evidence):
            if term not in searched:
                frontier_terms.append(term)
                operations.append({"tool": "search_source", "arguments": {"text": term, "offset": 0}})
        operations = operations[:12]
        searched.update(operation["arguments"]["text"] for operation in operations
                        if operation["tool"] == "search_source")
        if not operations:
            stagnant += 1
            break
        located = team.read_tool("batch_evidence", {"operations": operations})
        locator_results.append(located)
        total_operations += len(operations)
        paths = [path for path in _paths_from_tool_result(located) if path not in read_paths]
        # Definitions close paths; files merely importing the same class are
        # secondary. Put Foo.java/Foo.xml ahead of broad textual matches.
        frontier = set(frontier_terms)
        paths.sort(key=lambda path: (0 if path.rsplit("/", 1)[-1].rsplit(".", 1)[0] in frontier else 1,
                                     path))
        paths = paths[:8]
        reads = [{"tool": "read_file", "arguments": {"path": path}} for path in paths]
        before = len(evidence)
        if reads:
            read_result = team.read_tool("batch_evidence", {"operations": reads})
            read_results.append(read_result)
            team.collect_evidence("batch_evidence", read_result, evidence)
            total_operations += len(reads)
            read_paths.update(paths)
        if len(evidence) == before:
            stagnant += 1
            if stagnant >= 2:
                break
        else:
            stagnant = 0
    new_count = len(evidence) - len(base_evidence)
    stop_reason = ("closure_complete_or_bounded" if new_count
                   else "two_rounds_without_new_evidence" if stagnant >= 2 else "no_new_dependencies")
    trace = {"round": rounds, "operations": total_operations,
             "new_evidence": new_count, "new_paths": len(read_paths),
             "stagnant_rounds": stagnant, "stop_reason": stop_reason,
             "locator_results": locator_results, "read_results": read_results}
    return evidence, trace


def model_evidence_view(evidence, *, content_limit=32000):
    """Keep canonical full evidence server-side; send only a bounded packet view."""
    rows, remaining = [], content_limit
    for row in evidence.values():
        projected = {key: row.get(key) for key in (
            "evidence_id", "chunk_id", "relative_path", "start_line", "end_line",
            "content_sha256", "truncated") if key in row}
        content = row.get("content", "")
        take = min(len(content), max(0, remaining), 8000)
        projected["content"] = content[:take]
        projected["packet_truncated"] = take < len(content)
        remaining -= take
        rows.append(projected)
        if remaining <= 0:
            break
    return rows


def parse_validation_result(raw, packet, sketches, evidence):
    if not isinstance(raw, dict) or set(raw) != {"packet_id", "outcomes"}:
        raise ModelOutputError("路径验证结果必须包含packet_id和outcomes")
    if raw["packet_id"] != packet["id"] or not isinstance(raw["outcomes"], list):
        raise ModelOutputError("路径验证包编号或outcomes不合法")
    expected = set(packet["path_ids"])
    if {row.get("path_id") for row in raw["outcomes"] if isinstance(row, dict)} != expected:
        raise ModelOutputError("路径验证必须逐项覆盖验证包中的全部路径")
    for row in raw["outcomes"]:
        required = {"path_id", "outcome", "assessment", "counterevidence",
                    "limitations", "evidence_ids"}
        if not isinstance(row, dict) or set(row) - required - {"finding"} or not required <= set(row):
            raise ModelOutputError("路径验证字段不完整")
        if row["outcome"] not in {"supported", "refuted", "inconclusive"}:
            raise ModelOutputError("路径验证outcome不合法")
        require_text(row["assessment"], "assessment")
        require_text(row["counterevidence"], "counterevidence")
        require_strings(row["limitations"], "limitations", empty=True)
        require_refs(row["evidence_ids"], evidence)
        if row["outcome"] == "supported" and "finding" in row:
            parse_worker_finding(row["finding"], evidence)
        elif "finding" in row:
            raise ModelOutputError("非supported路径不得提交finding")
    return raw


def build_supported_findings(team, packet, result, sketches, evidence):
    supported = [row for row in result["outcomes"]
                 if row["outcome"] == "supported" and "finding" not in row]
    for row in supported:
        sketch = next(item for item in sketches if item["id"] == row["path_id"])
        refs = list(dict.fromkeys(row["evidence_ids"]))
        root = refs[0]
        cwe = {"object_level_authorization": "CWE-639", "function_level_authorization": "CWE-862",
               "path_traversal": "CWE-22", "command_injection": "CWE-78",
               "sql_injection": "CWE-89", "unsafe_deserialization": "CWE-502",
               "ssrf": "CWE-918", "template_injection": "CWE-1336", "xxe": "CWE-611",
               "xss": "CWE-79", "jndi_injection": "CWE-74", "open_redirect": "CWE-601",
               "jwt_verification_bypass": "CWE-347", "arbitrary_file_write": "CWE-73",
               "hardcoded_secret": "CWE-798", "security_misconfiguration": "CWE-16",
               "expression_injection": "CWE-917"}.get(sketch["candidate_type"])
        limitations = row["limitations"] or ["仅完成静态源码验证，未执行动态利用"]
        severity = "high" if sketch["candidate_type"] in {
            "command_injection", "unsafe_deserialization", "sql_injection", "xxe",
            "jndi_injection", "expression_injection", "template_injection",
            "jwt_verification_bypass", "arbitrary_file_write"} else "medium"
        row["finding"] = {
            "boundary": {"entry": sketch["entry"], "attacker_control": sketch["source"],
                         "asset": sketch["sink"], "trust_transition": f"{sketch['source']} 到 {sketch['sink']}",
                         "expected_control": sketch["control"], "observed_control": row["assessment"],
                         "unknowns": limitations, "evidence_ids": refs},
            "investigation": {"question": sketch["hypothesis"], "control_to_check": sketch["control"],
                              "counterevidence": row["counterevidence"],
                              "next_check": "独立复核证据引用、攻击前提和严重性",
                              "unknowns": limitations, "evidence_ids": refs},
            "review": {"outcome": "supported", "assessment": row["assessment"],
                       "counterevidence": row["counterevidence"], "limitations": limitations,
                       "evidence_ids": refs},
            "detail": {"title": f"{sketch['candidate_type']}：{sketch['entry']}",
                       "summary": sketch["hypothesis"],
                       "rootCause": {"summary": row["assessment"], "evidenceRefs": refs},
                       "attackPath": {"summary": sketch["hypothesis"],
                           "dataflow": {"summary": "输入沿已验证路径到达安全敏感操作",
                               "source": sketch["source"], "transformations": sketch["hops"],
                               "sink": sketch["sink"], "outcome": sketch["hypothesis"], "evidenceRefs": refs},
                           "reachability": {"summary": f"攻击者可从{sketch['entry']}触发路径",
                               "attacker": sketch["source"], "entrypoint": sketch["entry"],
                               "preconditions": ["满足验证记录中的攻击前提"],
                               "outcome": sketch["hypothesis"], "evidenceRefs": refs},
                           "impact": {"level": severity, "rationale": sketch["sink"]},
                           "likelihood": {"level": "medium", "rationale": row["assessment"]},
                           "limitations": limitations, "evidenceRefs": refs},
                       "severity": {"level": severity, "rationale": sketch["hypothesis"]},
                       "confidence": {"level": "high", "rationale": "独立路径验证判定supported"},
                       "remediation": f"在{sketch['entry']}到{sketch['sink']}之间实施并集中复用{sketch['control']}。",
                       "remediationTests": ["增加未授权或恶意输入被拒绝的回归测试"],
                       "preventiveControls": [sketch["control"]],
                       "evidenceNotes": [{"evidence_id": ref,
                           "role": "root_control" if ref == root else "propagation",
                           "explanation": "路径验证引用的源码证据"} for ref in refs],
                       "ruleId": sketch["candidate_type"].replace("_", "-"),
                       "taxonomy": {"category": sketch["surface"], "cwe": [cwe] if cwe else []},
                       "root_control": root}}
        parse_worker_finding(row["finding"], evidence)
    return result


VALIDATION_PROMPT = """你是一次性路径验证器。输入是后端固定的相关路径和已验证源码证据。
不调用工具，不扩大范围，不输出Markdown或解释，只返回一个可解析JSON对象。
security_context是用户明确给定的攻击者能力、入口、调用关系和范围完整性前提，必须用于可达性判断；
若它明确说明所给代码包含完整业务控制或不存在其他授权层，不得要求额外调用者/外部控制源码来推翻该前提。
代码自身是否执行安全检查仍须evidence支持。
对已批准读取的配置文件，危险配置值本身足以支持“静态配置缺陷”；把“仅在该配置实际激活时可达”写入limitations，
不得仅因没有运行时profile或网络暴露证明就判inconclusive。动态可达性影响严重性和前提，不抹去静态缺陷。
逐条判断漏洞假设：supported/refuted/inconclusive。输入packet.needs所列证据没有出现在evidence时，除非现有源码已决定性证明，
必须判inconclusive；暂未看到防护不能判supported，暂未看到漏洞也不能判refuted。
outcomes必须逐项覆盖packet.path_ids且不得添加其他路径。非supported项严格只包含以下六个字段：
{\"path_id\":\"原样复制路径ID\",\"outcome\":\"inconclusive\",\"assessment\":\"一句证据判断\",\
\"counterevidence\":\"一句最强反证或尚未核实的控制\",\"limitations\":[\"具体缺失证据\"],\"evidence_ids\":[\"只能复制输入中的真实evidence_id\"]}。
最外层严格为{\"packet_id\":\"原样复制包ID\",\"outcomes\":[...]}。
只有现有证据完整证明可利用控制失效时才可supported。验证器不要输出finding；后端会只为supported路径
启动专用Finding Builder。证据不足必须判inconclusive，不得为了进入后续阶段夸大结论。
总输出不超过900个中文字符；不要复述源码，不输出分析过程。"""


COMPACT_REPAIR_PROMPT = """修复上一次被截断的路径验证输出。只输出短JSON，不写分析，700字以内。
严格结构：{\"packet_id\":\"原ID\",\"outcomes\":[{\"path_id\":\"原ID\",\"outcome\":\"supported|refuted|inconclusive\",
\"assessment\":\"一句\",\"counterevidence\":\"一句\",\"limitations\":[\"一句\"],\"evidence_ids\":[\"真实ID\"]}]}。
security_context中的入口、攻击者能力和完整范围是给定前提；源码行为以证据为准。不要输出finding。"""


def run_validation_packet(team, packet_id):
    task = team.store.get(team.task_id)
    packet = next(row for row in task.get("validation_packets", []) if row["id"] == packet_id)
    record_stage(team.store, team.task_id, "path_validation", "running",
                 scope_id=packet_id, name="路径验证",
                 completed_units=0, total_units=len(packet.get("path_ids", [])),
                 metadata={"surface": packet.get("surface"),
                           "candidate_type": packet.get("candidate_type")})
    sketches = [row for row in task.get("path_sketches", []) if row["id"] in packet["path_ids"]]
    packet["sketches"] = sketches
    evidence = {}
    for worker in task.get("agent_tasks", []):
        evidence.update(worker.get("evidence", {}))
    evidence.update(task.get("evidence", {}))
    selected = {ref: evidence[ref] for ref in packet["evidence_ids"] if ref in evidence}
    selected, trace = supplement_packet_evidence(team, packet, selected)
    concise_trace = {key: value for key, value in trace.items()
                     if key not in {"locator_results", "read_results"}}
    packet["evidence_ids"] = list(selected)
    packet["supplement"] = concise_trace
    with team.lock:
        current = team.store.get(team.task_id)
        packets = current.get("validation_packets", [])
        current_packet = next(row for row in packets if row["id"] == packet_id)
        current_packet.update(evidence_ids=list(selected), supplement=concise_trace)
        team.store.update(team.task_id, validation_packets=packets,
                          evidence={**current.get("evidence", {}), **selected},
                          evidence_rounds=[*current.get("evidence_rounds", []),
                                           {"packet_id": packet_id, **concise_trace}])
    record_stage(team.store, team.task_id, "evidence_supplement", "completed",
                 scope_id=packet_id, name="批量补证",
                 completed_units=trace.get("round", 0), total_units=2,
                 tool_operations=trace.get("operations", 0),
                 new_evidence=trace.get("new_evidence", 0),
                 stop_reason=trace.get("stop_reason"),
                 metadata={"stagnant_rounds": trace.get("stagnant_rounds", 0),
                           "evidence_count": len(selected)})
    payload = {"packet": packet, "paths": sketches, "evidence": model_evidence_view(selected),
               "objective": task.get("objective"),
               "security_context": task.get("security_context"),
               "supplied_threat_model": task.get("supplied_threat_model"),
               "context_rule": "这是增量证据；用户给定安全上下文是审计前提，不是源码证据；未提供的旧源码不要假定其内容。"}
    model = team.model_factory()

    def compact_request():
        compact_evidence = [{key: row.get(key) for key in
                             ("evidence_id", "chunk_id", "relative_path", "start_line", "end_line")}
                            | {"content": row.get("content", "")[:1200]}
                            for row in list(selected.values())[:3]]
        compact = {"packet": packet, "paths": sketches,
                   "security_context": task.get("security_context"),
                   "evidence": compact_evidence}
        return team.request(team.model_factory(),
                            [{"role": "system", "content": COMPACT_REPAIR_PROMPT},
                             {"role": "user", "content": json.dumps(compact, ensure_ascii=False)}],
                            "path-validation:" + packet_id + ":repair")

    try:
        try:
            raw = team.request(model, [{"role": "system", "content": VALIDATION_PROMPT},
                                       {"role": "user", "content": json.dumps(payload, ensure_ascii=False)}],
                               "path-validation:" + packet_id)
            result = parse_validation_result(raw, packet, sketches, selected)
        except (ModelOutputError, ModelRequestError):
            # Empty content, malformed JSON and one provider timeout are all
            # recoverable with the same much smaller deterministic packet.
            # The retry is explicit in model_requests and happens at most once.
            raw = compact_request()
            result = parse_validation_result(raw, packet, sketches, selected)
        result = build_supported_findings(team, packet, result, sketches, selected)
        team.persist_path_validation(packet_id, result, selected)
        requests = team.store.get(team.task_id).get("model_requests", [])
        related = [row for row in requests if packet_id in str(row.get("agent_id", ""))]
        record_stage(team.store, team.task_id, "path_validation", "completed",
                     scope_id=packet_id, name="路径验证",
                     completed_units=len(result.get("outcomes", [])),
                     total_units=len(packet.get("path_ids", [])),
                     model_calls=len(related),
                     tokens=sum(row.get("total_tokens", 0) or 0 for row in related),
                     metadata={"outcomes": {value: sum(1 for row in result.get("outcomes", [])
                                                       if row.get("outcome") == value)
                                             for value in ("supported", "refuted", "inconclusive")}})
    except Exception as error:
        # Futures are otherwise easy to lose: persist a terminal packet state so
        # the final report cannot mistake an unvalidated path for a clean result.
        with team.lock:
            task = team.store.get(team.task_id)
            packets = task.get("validation_packets", [])
            target = next(row for row in packets if row["id"] == packet_id)
            target.update(status="failed", attempts=1,
                          error=f"{type(error).__name__}: {str(error)[:300]}")
            sketches_now = task.get("path_sketches", [])
            validations = list(task.get("path_validations", []))
            for sketch in sketches_now:
                if sketch.get("id") in target["path_ids"]:
                    sketch["status"] = "validation_failed"
                    validations = [row for row in validations
                                   if row.get("path_id") != sketch["id"]]
                    validations.append({
                        "path_id": sketch["id"], "packet_id": packet_id,
                        "outcome": "failed", "assessment": "路径验证未取得合法结论",
                        "counterevidence": "未形成有效反证判断", "limitations": [
                            f"{type(error).__name__}: {str(error)[:200]}"],
                        "evidence_ids": list(target.get("evidence_ids", [])),
                    })
            team.store.update(team.task_id, validation_packets=packets,
                              path_sketches=sketches_now, path_validations=validations)
        record_stage(team.store, team.task_id, "path_validation", "failed",
                     scope_id=packet_id, name="路径验证",
                     completed_units=0, total_units=len(packet.get("path_ids", [])),
                     error=f"{type(error).__name__}: {str(error)[:300]}")
        team.changed.set()
