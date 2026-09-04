"""调查阶段的安全边界笔记；不是已验证漏洞或完整威胁模型。"""

from dataclasses import dataclass

from secval.models.audit_contracts import ModelOutputError


@dataclass(frozen=True)
class SecurityBoundary:
    entry: str
    attacker_control: str
    asset: str
    trust_transition: str
    expected_control: str
    observed_control: str
    unknowns: list[str]
    evidence_ids: list[str]

    @classmethod
    def parse(cls, raw, evidence):
        fields = {"entry", "attacker_control", "asset", "trust_transition",
                  "expected_control", "observed_control", "unknowns", "evidence_ids"}
        if not isinstance(raw, dict) or set(raw) != fields:
            raise ModelOutputError("边界记录字段不完整或包含未知字段")
        for key in fields - {"unknowns", "evidence_ids"}:
            if not isinstance(raw[key], str) or not 1 <= len(raw[key].strip()) <= 2000:
                raise ModelOutputError("边界描述必须为1到2000字符")
        for key in ("unknowns", "evidence_ids"):
            values = raw[key]
            if (not isinstance(values, list) or not 1 <= len(values) <= 20
                    or any(not isinstance(v, str) or not 1 <= len(v.strip()) <= 2000 for v in values)):
                raise ModelOutputError("边界未知项和证据必须为非空字符串数组，最多20项")
        refs = raw["evidence_ids"]
        if len(set(refs)) != len(refs) or any(ref not in evidence for ref in refs):
            raise ModelOutputError("边界引用必须是不重复的已读证据ID")
        return cls(**raw)
