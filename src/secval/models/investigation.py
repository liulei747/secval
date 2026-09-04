"""关联安全边界的待调查问题；不允许创建时直接宣称验证完成。"""

from dataclasses import dataclass, field

from secval.models.audit_contracts import ModelOutputError


@dataclass(frozen=True)
class Investigation:
    boundary_id: str
    question: str
    control_to_check: str
    counterevidence: str
    next_check: str
    unknowns: list[str]
    evidence_ids: list[str]
    baseline_question_ids: list[str] = field(default_factory=list)

    @classmethod
    def parse(cls, raw, boundaries, evidence, baseline=None):
        fields = set(cls.__dataclass_fields__) - {"baseline_question_ids"}
        if not isinstance(raw, dict) or not fields <= set(raw) or set(raw) - fields - {"baseline_question_ids"}:
            raise ModelOutputError("调查问题字段不完整或包含未知字段")
        links = raw.get("baseline_question_ids", [])
        known = {question["id"] for question in (baseline or {}).get("questions", [])}
        if (not isinstance(links, list) or len(links) > 20 or any(not isinstance(link, str) for link in links)
                or len(set(links)) != len(links) or any(link not in known for link in links)):
            raise ModelOutputError("只能关联本任务已有且不重复的基线问题ID")
        for key in fields - {"unknowns", "evidence_ids"}:
            if not isinstance(raw[key], str) or not 1 <= len(raw[key].strip()) <= 2000:
                raise ModelOutputError("调查描述必须为1到2000字符")
        if raw["boundary_id"] not in {item["id"] for item in boundaries}:
            raise ModelOutputError("调查必须关联本任务已经记录的边界ID")
        for key in ("unknowns", "evidence_ids"):
            items = raw[key]
            if (not isinstance(items, list) or not 1 <= len(items) <= 20
                    or any(not isinstance(v, str) or not 1 <= len(v.strip()) <= 2000 for v in items)):
                raise ModelOutputError("调查未知项和证据必须为非空字符串数组，最多20项")
        refs = raw["evidence_ids"]
        if len(set(refs)) != len(refs) or any(ref not in evidence for ref in refs):
            raise ModelOutputError("调查引用必须是不重复的已读证据ID")
        return cls(**raw)
