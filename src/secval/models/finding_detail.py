"""Secval候选详情契约，不冒充供应商完整Schema。"""

import re

from secval.models.audit_contracts import ModelOutputError

FIELDS = {"investigation_id", "title", "summary", "rootCause", "attackPath",
          "severity", "confidence", "remediation", "remediationTests", "preventiveControls", "evidenceNotes",
          "ruleId", "taxonomy", "root_control"}


def parse_finding_detail(raw, investigations, evidence):
    if not isinstance(raw, dict) or set(raw) != FIELDS:
        raise ModelOutputError("发现详情字段不完整或包含未知字段")
    for key in ("investigation_id", "title", "summary", "remediation"):
        require_text(raw[key])
    if raw["investigation_id"] not in {i["id"] for i in investigations}:
        raise ModelOutputError("发现详情必须关联已有调查问题")
    require_text(raw["ruleId"])
    if not re.fullmatch(r"[a-z0-9][a-z0-9._/-]{0,119}", raw["ruleId"]):
        raise ModelOutputError("ruleId必须是小写漏洞族标识")
    taxonomy = raw["taxonomy"]
    if not isinstance(taxonomy, dict) or set(taxonomy) != {"category", "cwe"}:
        raise ModelOutputError("taxonomy需要category和cwe")
    require_text(taxonomy["category"])
    cwes = taxonomy["cwe"]
    if (not isinstance(cwes, list) or len(cwes) > 10
            or any(not isinstance(c, str) or not re.fullmatch(r"CWE-[1-9][0-9]*", c) for c in cwes)
            or len(set(cwes)) != len(cwes)):
        raise ModelOutputError('taxonomy.cwe必须是最多10项的不重复字符串数组，元素形式例如"CWE-20"；'
                               '不是数字或对象，不确定时使用[]')
    require_text(raw["root_control"])
    for key in ("rootCause", "attackPath"):
        section = raw[key]
        expected = {"summary", "evidenceRefs"}
        if key == "attackPath":
            expected |= {"dataflow", "reachability", "impact", "likelihood", "limitations"}
        if not isinstance(section, dict) or set(section) != expected:
            raise ModelOutputError("根因和攻击路径需要summary及evidenceRefs")
        require_text(section["summary"])
        refs = section["evidenceRefs"]
        require_array(refs)
        if len(set(refs)) != len(refs) or any(ref not in evidence for ref in refs):
            raise ModelOutputError("发现详情只能引用不重复的已读证据")
    notes = raw["evidenceNotes"]
    if not isinstance(notes, list) or not 1 <= len(notes) <= 40:
        raise ModelOutputError("证据说明需要1到40项")
    described = set()
    for note in notes:
        if not isinstance(note, dict) or set(note) != {"evidence_id", "role", "explanation"}:
            raise ModelOutputError("证据说明只允许evidence_id、role、explanation，不允许改写源码")
        for value in note.values():
            require_text(value)
        if note["evidence_id"] not in evidence or note["evidence_id"] in described:
            raise ModelOutputError("evidenceNotes中每个evidence_id只能出现一次且必须已读；"
                                   "同一证据承担多个作用时合并为一项，根因证据使用root_control角色")
        if note["role"] not in {"user_input", "entrypoint", "propagation", "root_control", "sink", "outcome", "expected_control"}:
            raise ModelOutputError("证据角色不合法")
        described.add(note["evidence_id"])
    required_refs = set(raw["rootCause"]["evidenceRefs"]) | set(raw["attackPath"]["evidenceRefs"])
    if described != required_refs:
        raise ModelOutputError("证据说明必须恰好覆盖根因和攻击路径引用")
    if raw["root_control"] not in raw["rootCause"]["evidenceRefs"] or not any(
        note["evidence_id"] == raw["root_control"] and note["role"] == "root_control" for note in notes
    ):
        raise ModelOutputError("root_control必须引用根因中标记为root_control的证据")
    path = raw["attackPath"]
    for key, fields in (
        ("dataflow", {"summary", "source", "transformations", "sink", "outcome", "evidenceRefs"}),
        ("reachability", {"summary", "attacker", "entrypoint", "preconditions", "outcome", "evidenceRefs"}),
    ):
        section = path[key]
        if not isinstance(section, dict) or set(section) != fields:
            raise ModelOutputError("攻击路径数据流或可达性字段不完整")
        for field in fields - {"transformations", "preconditions", "evidenceRefs"}:
            require_text(section[field])
        for field in fields & {"transformations", "preconditions"}:
            values = section[field]
            if not isinstance(values, list) or len(values) > 20:
                raise ModelOutputError("路径变化和前提必须为最多20项的数组")
            for value in values:
                require_text(value)
        refs = section["evidenceRefs"]
        require_array(refs)
        if len(set(refs)) != len(refs) or any(ref not in path["evidenceRefs"] for ref in refs):
            raise ModelOutputError("数据流和可达性引用必须包含在路径证据中")
    require_array(path["limitations"])
    for key in ("impact", "likelihood"):
        rating = path[key]
        if not isinstance(rating, dict) or set(rating) != {"level", "rationale"}:
            raise ModelOutputError("影响与可能性需要level及rationale")
        require_text(rating["level"])
        require_text(rating["rationale"])
        if rating["level"] not in {"high", "medium", "low", "unknown"}:
            raise ModelOutputError("影响与可能性评级不合法")
    for key in ("severity", "confidence"):
        rating = raw[key]
        if not isinstance(rating, dict) or set(rating) != {"level", "rationale"}:
            raise ModelOutputError("评级必须包含level和rationale")
        require_text(rating["level"])
        require_text(rating["rationale"])
        levels = {"low", "medium", "high", "critical"} if key == "severity" else {"low", "medium", "high"}
        if rating["level"] not in levels:
            raise ModelOutputError("评级不合法")
    for key in ("remediationTests", "preventiveControls"):
        require_array(raw[key])
    return raw


def require_text(value):
    if not isinstance(value, str) or not 1 <= len(value.strip()) <= 4000:
        raise ModelOutputError("发现详情文本必须为1到4000字符")


def require_array(value):
    if not isinstance(value, list) or not 1 <= len(value) <= 20:
        raise ModelOutputError("发现详情数组必须为1到20项")
    for item in value:
        require_text(item)
