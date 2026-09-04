"""同一调查模型的静态核查意见，不代表独立验证或动态复现。"""

from dataclasses import dataclass

from secval.models.audit_contracts import ModelOutputError


@dataclass(frozen=True)
class InvestigationReview:
    investigation_id: str
    outcome: str
    assessment: str
    counterevidence: str
    limitations: list[str]
    evidence_ids: list[str]

    @classmethod
    def parse(cls, raw, investigations, evidence):
        if not isinstance(raw, dict) or set(raw) != set(cls.__dataclass_fields__):
            raise ModelOutputError("核查记录字段不完整或包含未知字段")
        for key in ("investigation_id", "outcome", "assessment", "counterevidence"):
            if not isinstance(raw[key], str) or not 1 <= len(raw[key].strip()) <= 2000:
                raise ModelOutputError("核查描述必须为1到2000字符")
        if raw["investigation_id"] not in {item["id"] for item in investigations}:
            raise ModelOutputError("只能核查本任务已经登记的调查问题")
        if raw["outcome"] not in {"supported", "refuted", "inconclusive"}:
            raise ModelOutputError("核查结果只能为supported/refuted/inconclusive")
        for key in ("limitations", "evidence_ids"):
            items = raw[key]
            if (not isinstance(items, list) or not 1 <= len(items) <= 20
                    or any(not isinstance(v, str) or not 1 <= len(v.strip()) <= 2000 for v in items)):
                raise ModelOutputError("核查限制和证据必须为非空字符串数组，最多20项")
        refs = raw["evidence_ids"]
        if len(set(refs)) != len(refs) or any(ref not in evidence for ref in refs):
            raise ModelOutputError("核查引用必须是不重复的已读证据ID")
        return cls(**raw)
