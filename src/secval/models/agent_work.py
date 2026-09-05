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


def parse_assignment(arguments, evidence):
    if not isinstance(arguments, dict) or set(arguments) != {"title", "question", "evidence_ids"}:
        raise ModelOutputError("分派任务需要title、question、evidence_ids")
    require_text(arguments["title"], "title", 120)
    require_text(arguments["question"], "question")
    require_refs(arguments["evidence_ids"], evidence)
    return arguments


def parse_work_result(raw, evidence):
    if not isinstance(raw, dict) or set(raw) != {"summary", "questions", "unknowns", "reviewed_files"}:
        raise ModelOutputError("子任务结果需要summary、questions、unknowns、reviewed_files")
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
    import json
    if len(json.dumps(raw, ensure_ascii=False)) > 18000:
        raise ModelOutputError("子任务结果过长，请精简描述，不删除反证和未知项")
    return raw
