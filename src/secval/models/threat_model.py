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
        cls._fact(raw["summary"], evidence, "summary")
        for key in ("assets", "attackerCapabilities", "securityObjectives", "assumptions"):
            rows = raw[key]
            if not isinstance(rows, list) or not 1 <= len(rows) <= 30:
                raise ModelOutputError("模型各项必须包含1到30条事实或假设")
            for index, row in enumerate(rows):
                cls._fact(row, evidence, f"{key}[{index}]")
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
    def _fact(raw, evidence, field_name="fact"):
        if not isinstance(raw, dict) or set(raw) != {"text", "origin", "evidence_ids"}:
            raise ModelOutputError(f"{field_name}必须是仅含text、origin、evidence_ids的对象，不能是字符串；"
                                   '格式示例：{"text":"待核查事实","origin":"unknown","evidence_ids":[]}')
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


def derive_threat_model(boundaries, evidence):
    """Derive a conservative structured model from the validated boundary ledger.

    This does not invent deployment facts. Every concrete fact is copied from a
    recorded boundary and retains that boundary's evidence references.
    """

    def facts(field):
        rows = []
        seen = set()
        for boundary in boundaries:
            value = str(boundary.get(field, "")).strip()
            refs = [ref for ref in boundary.get("evidence_ids", []) if ref in evidence][:20]
            if not value or not refs or value in seen:
                continue
            seen.add(value)
            rows.append({"text": value, "origin": "code", "evidence_ids": refs})
            if len(rows) == 30:
                break
        return rows

    boundary_ids = [row["id"] for row in boundaries if row.get("id")][:30]
    assets = facts("asset")
    attackers = facts("attacker_control")
    objectives = facts("expected_control")
    if not boundary_ids or not assets or not attackers or not objectives:
        return None
    model = {
        "summary": {"text": "由已登记信任边界及其源码证据确定性派生；未登记的部署边界仍未知。",
                    "origin": "unknown", "evidence_ids": []},
        "assets": assets,
        "trustBoundaries": boundary_ids,
        "attackerCapabilities": attackers,
        "securityObjectives": objectives,
        "assumptions": [{"text": "未登记入口、外部基础设施与运行期控制不在该派生模型证明范围内。",
                         "origin": "unknown", "evidence_ids": []}],
    }
    return ThreatModel.parse(model, boundaries, evidence)
