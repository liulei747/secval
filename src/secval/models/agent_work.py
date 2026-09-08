"""子调查任务的输入与结果：所有结论只能引用实际读取的证据。"""

from secval.models.audit_contracts import ModelOutputError


def require_text(value, name, limit=2000):
    if not isinstance(value, str) or not 1 <= len(value.strip()) <= limit:
        raise ModelOutputError(f"{name}必须为非空文本，且不超过{limit}字符")
    return value


def require_strings(value, name, *, empty=False):
    if not isinstance(value, list) or len(value) > 20 or (not value and not empty):
        raise ModelOutputError(f"{name}必须为最多20项的字符串数组")
    for item in value:
        require_text(item, name)
    return value


def require_refs(value, evidence):
    require_strings(value, "evidence_ids")
    if len(set(value)) != len(value) or any(ref not in evidence for ref in value):
        raise ModelOutputError("只能引用本子任务已读且不重复的证据ID")
    return value


NEED_KINDS = {"symbol_definition", "callers", "callees", "data_path", "config_lookup",
              "route_guard", "template_resolution", "file_read", "source_search"}


def parse_evidence_need(raw):
    """Normalize legacy prose while making new probes emit executable requests."""
    if isinstance(raw, str) and raw.strip():
        return {"kind": "source_search", "target": raw.strip(),
                "reason": raw.strip(), "required_for": "validation"}
    required = {"kind", "target", "reason", "required_for"}
    if not isinstance(raw, dict) or set(raw) != required or raw.get("kind") not in NEED_KINDS:
        raise ModelOutputError("need需要kind、target、reason、required_for且kind受控")
    for name in required - {"kind"}:
        require_text(raw[name], "need." + name, 500)
    if raw["kind"] == "file_read" and not any(mark in raw["target"] for mark in ("/", "\\", ".java", ".py", ".js", ".xml")):
        raw = {**raw, "kind": "source_search"}
    return raw


def parse_assignment(arguments, evidence):
    if not isinstance(arguments, dict) or set(arguments) != {"title", "question", "evidence_ids"}:
        raise ModelOutputError("分派任务需要title、question、evidence_ids")
    require_text(arguments["title"], "title", 120)
    require_text(arguments["question"], "question")
    require_refs(arguments["evidence_ids"], evidence)
    return arguments


def parse_work_result(raw, evidence):
    base = {"summary", "questions", "unknowns", "reviewed_files"}
    if not isinstance(raw, dict) or not base <= set(raw) or set(raw) - base - {"findings", "path_sketches"}:
        raise ModelOutputError("子任务结果需要summary、questions、unknowns、reviewed_files，可选findings和path_sketches")
    require_text(raw["summary"], "summary")
    require_strings(raw["unknowns"], "unknowns")
    if not isinstance(raw["questions"], list) or len(raw["questions"]) > 12:
        raise ModelOutputError("questions最多12项")
    for question in raw["questions"]:
        required = {"question", "outcome", "assessment", "counterevidence", "unknowns", "evidence_ids"}
        if not isinstance(question, dict) or set(question) != required:
            raise ModelOutputError("子任务问题字段不完整")
        for name in ("question", "assessment", "counterevidence"):
            require_text(question[name], name)
        if question["outcome"] not in ("supported", "refuted", "inconclusive"):
            raise ModelOutputError("子任务问题outcome不合法")
        require_strings(question["unknowns"], "unknowns")
        require_refs(question["evidence_ids"], evidence)
    # 不接受只搜索过、只读过片段的文件冒充完整安全审阅。
    from secval.models.file_review import parse_file_review
    if not isinstance(raw["reviewed_files"], list) or len(raw["reviewed_files"]) > 20:
        raise ModelOutputError("reviewed_files最多20项")
    for review in raw["reviewed_files"]:
        parse_file_review(review, evidence)
    findings = raw.get("findings", [])
    if not isinstance(findings, list) or len(findings) > 8:
        raise ModelOutputError("findings必须为最多8项的数组")
    for finding in findings:
        parse_worker_finding(finding, evidence)
    sketches = raw.get("path_sketches", [])
    if not isinstance(sketches, list) or len(sketches) > 12:
        raise ModelOutputError("path_sketches必须为最多12项的数组")
    allowed_surfaces = {"authentication", "authorization", "file", "command_execution",
                        "deserialization", "injection", "outbound_request", "data_exposure",
                        "trust_boundary", "configuration", "other"}
    allowed_types = {"auth_bypass", "session_flaw", "object_level_authorization",
                     "function_level_authorization", "tenant_isolation", "sql_injection",
                     "template_injection", "expression_injection", "command_injection",
                     "path_traversal", "unsafe_upload", "unsafe_deserialization", "ssrf",
                     "sensitive_data_exposure", "message_trust", "xxe", "xss",
                     "jndi_injection", "open_redirect", "jwt_verification_bypass",
                     "arbitrary_file_write", "hardcoded_secret", "security_misconfiguration",
                     "unknown"}
    surface_aliases = {"access_control": "authorization", "access-control": "authorization",
                       "idor": "authorization", "template": "injection", "template_injection": "injection",
                       "command": "command_execution", "file_access": "file", "ssrf": "outbound_request",
                       "information_disclosure": "data_exposure", "sensitive_data": "data_exposure",
                       "http": "other", "web": "other", "config": "configuration"}
    type_aliases = {"idor": "object_level_authorization", "bola": "object_level_authorization",
                    "missing_authorization": "function_level_authorization", "command_execution": "command_injection",
                    "directory_traversal": "path_traversal", "file_upload": "unsafe_upload",
                    "deserialization": "unsafe_deserialization", "data_exposure": "sensitive_data_exposure",
                    "stored_xss": "xss", "reflected_xss": "xss", "jwt_bypass": "jwt_verification_bypass",
                    "file_write": "arbitrary_file_write", "config": "security_misconfiguration",
                    "sqli_order_by": "sql_injection", "sqli_where": "sql_injection",
                    "sqli_limit": "sql_injection", "sqli": "sql_injection"}
    for sketch in sketches:
        required = {"surface", "candidate_type", "entry", "source", "hops", "sink", "control",
                    "hypothesis", "needs", "evidence_ids"}
        if not isinstance(sketch, dict) or set(sketch) != required:
            raise ModelOutputError("path_sketch字段不完整")
        sketch["surface"] = surface_aliases.get(sketch["surface"], sketch["surface"])
        sketch["candidate_type"] = type_aliases.get(sketch["candidate_type"], sketch["candidate_type"])
        if sketch["surface"] not in allowed_surfaces:
            raise ModelOutputError("path_sketch.surface不合法")
        if sketch["candidate_type"] not in allowed_types:
            raise ModelOutputError("path_sketch.candidate_type不合法")
        for name in ("entry", "source", "sink", "control", "hypothesis"):
            require_text(sketch[name], name, 500)
        # One-shot probes do not get a format-repair conversation. Normalize only
        # unambiguous scalar/empty variants; semantic fields and evidence remain strict.
        for name in ("hops",):
            if sketch[name] is None:
                sketch[name] = []
            elif isinstance(sketch[name], str):
                sketch[name] = [sketch[name]] if sketch[name].strip() else []
        require_strings(sketch["hops"], "hops", empty=True)
        if sketch["needs"] is None:
            sketch["needs"] = []
        elif isinstance(sketch["needs"], (str, dict)):
            sketch["needs"] = [sketch["needs"]]
        if not isinstance(sketch["needs"], list) or len(sketch["needs"]) > 6:
            raise ModelOutputError("needs必须为最多6项的结构化数组")
        sketch["needs"] = [parse_evidence_need(item) for item in sketch["needs"]]
        require_refs(sketch["evidence_ids"], evidence)
    import json
    if len(json.dumps(raw, ensure_ascii=False)) > 18000:
        raise ModelOutputError("子任务结果过长，请精简描述，不删除反证和未知项")
    return raw


def parse_worker_finding(raw, evidence):
    """Validate a complete worker candidate without trusting worker-generated IDs."""
    fields = {"boundary", "investigation", "review", "detail"}
    if not isinstance(raw, dict) or set(raw) != fields:
        raise ModelOutputError("worker finding需要boundary、investigation、review、detail")
    from dataclasses import asdict
    from secval.models.security_boundary import SecurityBoundary
    from secval.models.investigation import Investigation
    from secval.models.investigation_review import InvestigationReview
    from secval.models.finding_detail import parse_finding_detail

    boundary = {**asdict(SecurityBoundary.parse(raw["boundary"], evidence)), "id": "worker-boundary"}
    investigation_raw = {**raw["investigation"], "boundary_id": boundary["id"]}
    investigation = {**asdict(Investigation.parse(investigation_raw, [boundary], evidence)),
                     "id": "worker-investigation"}
    review_raw = {**raw["review"], "investigation_id": investigation["id"]}
    review = InvestigationReview.parse(review_raw, [investigation], evidence)
    if review.outcome != "supported":
        raise ModelOutputError("findings只接受supported候选；其他结论放入questions")
    detail_raw = {**raw["detail"], "investigation_id": investigation["id"]}
    parse_finding_detail(detail_raw, [investigation], evidence)
    return raw
