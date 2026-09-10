"""Candidate discovery provenance shared by the migration pipeline."""

from copy import deepcopy

ORIGIN_KINDS = frozenset({"deterministic", "heuristic", "graph", "model", "external"})
CONFIRMATION_CAPABILITIES = frozenset({"deterministic", "graph", "external"})


def candidate_origin(kind, producer, *, role="primary", capability="evidence"):
    """Create a controlled provenance item without trusting producer labels as semantics."""
    if kind not in ORIGIN_KINDS:
        raise ValueError(f"未知候选来源类型: {kind}")
    if role not in {"primary", "corroborating"}:
        raise ValueError(f"未知候选来源角色: {role}")
    if capability not in {"bootstrap_hint", "evidence"}:
        raise ValueError(f"未知候选来源能力: {capability}")
    if not isinstance(producer, str) or not producer.strip():
        raise ValueError("候选来源生成器不能为空")
    if kind == "heuristic" and capability != "bootstrap_hint":
        raise ValueError("启发式来源只能作为bootstrap hint")
    if kind == "model" and capability != "bootstrap_hint":
        raise ValueError("模型来源只能提出候选，不能作为确认事实")
    return {"kind": kind, "producer": producer.strip(), "role": role,
            "capability": capability}


def append_candidate_origin(candidate, origin):
    """Append one origin deterministically while preserving historical candidate fields."""
    checked = candidate_origin(**origin)
    result = deepcopy(candidate)
    origins = list(result.get("origins", []))
    identity = (checked["kind"], checked["producer"], checked["role"], checked["capability"])
    if identity not in {
        (row.get("kind"), row.get("producer"), row.get("role"), row.get("capability"))
        for row in origins
    }:
        origins.append(checked)
    result["origins"] = origins
    return result


def can_confirm_from_origins(candidate):
    """Return whether at least one non-hint machine evidence source supports adjudication."""
    return any(row.get("kind") in CONFIRMATION_CAPABILITIES
               and row.get("capability") == "evidence"
               for row in candidate.get("origins", []))
