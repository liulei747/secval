"""Prefill path sketches are compact, evidence-bound, durable pipeline records."""

import pytest

from secval.models.agent_work import parse_work_result
from secval.models.audit_contracts import ModelOutputError
from secval.services.agent_team import AgentTeam
from secval.services.path_validation_pipeline import build_validation_packets, _need_operations


def test_symbol_need_prioritizes_exact_member_and_owner():
    operations = _need_operations({"kind": "symbol_definition",
                                   "target": "com.example.service.DocumentService#loadDocument"})
    assert operations[:2] == [
        {"tool": "find_symbol", "arguments": {"text": "DocumentService", "offset": 0}},
        {"tool": "find_symbol", "arguments": {"text": "loadDocument", "offset": 0}},
    ]
    assert all(row["arguments"]["text"] not in {"com", "example", "service"}
               for row in operations)


def test_symbol_need_expands_compact_member_group():
    operations = _need_operations({"kind": "symbol_definition",
                                   "target": "DocumentService.loadDocument/storeDocument"})
    assert [row["arguments"]["text"] for row in operations] == [
        "DocumentService", "loadDocument", "storeDocument",
        "DocumentService",
    ]


def result(sketch):
    return {"summary": "one-shot probe", "questions": [], "unknowns": ["validation pending"],
            "reviewed_files": [], "findings": [], "path_sketches": [sketch]}


def sketch(evidence_id="e-1"):
    return {"surface": "authorization", "candidate_type": "object_level_authorization",
            "entry": "Controller.get", "source": "request.id",
            "hops": ["Service.get"], "sink": "DAO lookup", "control": "method permission",
            "hypothesis": "object ownership may be missing", "needs": ["DAO data scope"],
            "evidence_ids": [evidence_id]}


def test_path_sketch_is_validated_and_materialized_once():
    parsed = parse_work_result(result(sketch()), {"e-1": {}})
    rows = AgentTeam._merge_path_sketches([], parsed, "agent-2")
    normalized = sketch()
    normalized["needs"] = [{"kind": "source_search", "target": "DAO data scope",
                            "reason": "DAO data scope", "required_for": "validation"}]
    assert rows == [{**normalized, "id": "agent-2:path-1", "status": "queued_for_validation",
                     "source_id": "agent-2"}]
    assert AgentTeam._merge_path_sketches(rows, parsed, "agent-2") == rows


def test_path_sketch_cannot_reference_unread_evidence():
    with pytest.raises(ModelOutputError):
        parse_work_result(result(sketch("invented")), {"e-1": {}})


def test_one_shot_probe_normalizes_unambiguous_list_variants():
    raw = sketch()
    raw.update(hops="Service.get", needs=None)
    parsed = parse_work_result(result(raw), {"e-1": {}})
    assert parsed["path_sketches"][0]["hops"] == ["Service.get"]
    assert parsed["path_sketches"][0]["needs"] == []


def test_structured_need_is_preserved():
    raw = sketch()
    need = {"kind": "symbol_definition", "target": "OrderService.fetch",
            "reason": "inspect owner check", "required_for": "authorization"}
    raw["needs"] = [need]
    parsed = parse_work_result(result(raw), {"e-1": {}})
    assert parsed["path_sketches"][0]["needs"] == [need]


def test_unambiguous_security_enum_aliases_are_normalized():
    raw = sketch()
    raw.update(surface="access_control", candidate_type="idor")
    parsed = parse_work_result(result(raw), {"e-1": {}})["path_sketches"][0]
    assert (parsed["surface"], parsed["candidate_type"]) == (
        "authorization", "object_level_authorization")


def test_related_paths_share_one_bounded_validation_packet():
    rows = []
    for number in range(2):
        rows.append({**sketch(), "id": f"probe:path-{number}",
                     "status": "queued_for_validation", "source_id": "probe"})
    packets = build_validation_packets(rows)
    assert len(packets) == 1
    assert packets[0]["path_ids"] == ["probe:path-0", "probe:path-1"]
    assert packets[0]["evidence_ids"] == ["e-1"]
