"""生成模型区分代码事实、假设和未知项，保留已读证据出处。"""

from dataclasses import dataclass

from secval.models.audit_contracts import ModelOutputError


@dataclass(frozen=True)
class ThreatModel:
    summary: dict
    assets: list[dict]
    trustBoundaries: list[str]
    attackerCapabilities: list[dict]
    securityObjectives: list[dict]
    assumptions: list[dict]

    @classmethod
    def parse(cls, raw, boundaries, evidence):
        if not isinstance(raw, dict) or set(raw) != set(cls.__dataclass_fields__):
            raise ModelOutputError("威胁模型字段不完整或包含未知字段")
        cls._fact(raw["summary"], evidence)
        for key in ("assets", "attackerCapabilities", "securityObjectives", "assumptions"):
            rows = raw[key]
            if not isinstance(rows, list) or not 1 <= len(rows) <= 30:
                raise ModelOutputError("模型各项必须包含1到30条事实或假设")
            for row in rows:
                cls._fact(row, evidence)
        ids = raw["trustBoundaries"]
        if (not isinstance(ids, list) or len(ids) > 30
                or any(not isinstance(value, str) for value in ids)
                or len(set(ids)) != len(ids)
                or any(value not in {b["id"] for b in boundaries} for value in ids)):
            raise ModelOutputError("模型边界必须引用不重复的已记录边界ID")
        if not ids and not any(f["origin"] == "unknown" for f in raw["assumptions"]):
            raise ModelOutputError("没有边界时必须保留未知项")
        return cls(**raw)

    @staticmethod
    def _fact(raw, evidence):
        if not isinstance(raw, dict) or set(raw) != {"text", "origin", "evidence_ids"}:
            raise ModelOutputError("模型事实需要text、origin和evidence_ids")
        if not isinstance(raw["text"], str) or not 1 <= len(raw["text"].strip()) <= 2000:
            raise ModelOutputError("模型事实必须为1到2000字符")
        if not isinstance(raw["origin"], str) or raw["origin"] not in {"code", "assumption", "unknown"}:
            raise ModelOutputError("模型事实来源只能为code/assumption/unknown")
        refs = raw["evidence_ids"]
        if (not isinstance(refs, list) or len(refs) > 20
                or any(not isinstance(ref, str) for ref in refs)
                or len(set(refs)) != len(refs) or any(ref not in evidence for ref in refs)):
            raise ModelOutputError("模型事实只能引用不重复的已读证据")
        if raw["origin"] == "code" and not refs:
            raise ModelOutputError("代码事实必须有已读证据")
