"""复核输入身份必须随前提、边界变化，且不受字典插入顺序影响。"""

from copy import deepcopy
from unittest.mock import MagicMock

import pytest

from secval.models.audit_contracts import ModelOutputError
from secval.models.investigation_review import InvestigationReview
from secval.services.independent_review import (
    _prefetch_candidate_context,
    _prefetch_candidate_dependencies,
    review_evidence_matches,
    review_packet,
)
from tests.audit.test_agent_team import demo_row
from tests.audit.test_service_flow import candidate_detail


def test_review_input_identity_tracks_context_and_boundary():
    model = MagicMock()
    model.next_action.return_value = {
        "investigation_id": "i", "outcome": "inconclusive", "assessment": "证据不足",
        "counterevidence": "上游未知", "limitations": ["静态检查"], "evidence_ids": ["read-1"],
    }
    investigation = {"id": "i", "question": "检查归属", "evidence_ids": ["read-1"]}
    boundary = {"entry": "fetch", "asset": "order", "evidence_ids": ["read-1"]}
    evidence = {"read-1": demo_row()}

    def fingerprint(context, selected_boundary=boundary):
        return review_packet(model, investigation, selected_boundary, evidence,
                             user_context=context)["input_sha256"]

    original = fingerprint({"scope": "a", "assumption": "private"})
    assert original == fingerprint({"assumption": "private", "scope": "a"})
    assert original != fingerprint({"scope": "a", "assumption": "public"})
    assert original != fingerprint({"scope": "b", "assumption": "private"})
    assert original != fingerprint({"scope": "a", "assumption": "private"},
                                   {**boundary, "asset": "other"})
    scope = {"index_run_id": "run-1", "source_snapshot_id": "source-1", "view_id": "old"}
    context = {"scope": scope}
    initial = fingerprint(context)
    assert initial == fingerprint({"scope": {**scope, "view_id": "new"}})
    assert initial != fingerprint({"scope": {**scope, "index_run_id": "run-2"}})
    assert context["scope"]["view_id"] == "old"


def test_review_tracks_additional_evidence_and_rejects_changes():
    model, tools = MagicMock(), MagicMock()
    model.next_action.side_effect = [
        {"tool": "read_file", "arguments": {"path": "SafeOrderService.java"}},
        {"investigation_id": "i", "outcome": "inconclusive", "assessment": "证据不足",
         "counterevidence": "上游未知", "limitations": ["静态检查"], "evidence_ids": ["read-2"]},
    ]
    tools.call.return_value = {"rows": [demo_row("SafeOrderService.java")]}
    evidence = {"read-1": demo_row()}
    review = review_packet(model, {"id": "i", "question": "q", "evidence_ids": ["read-1"]},
        {"entry": "fetch", "asset": "order", "evidence_ids": ["read-1"]}, evidence, tools=tools)
    assert not review_evidence_matches(review, evidence)
    evidence["read-2"] = demo_row("SafeOrderService.java")
    assert review_evidence_matches(review, evidence)
    changed = deepcopy(evidence)
    changed["read-2"]["content"] += " changed"
    assert not review_evidence_matches(review, changed)
    changed = deepcopy(evidence)
    changed["read-2"]["relative_path"] = "Other.java"
    assert not review_evidence_matches(review, changed)
    assert not review_evidence_matches({}, evidence)


def test_candidate_review_prefetches_imported_repository_types():
    tools = MagicMock()
    tools.call.side_effect = [
        {"items": [
            {"tool": "find_symbol", "result": {"rows": []}},
            {"tool": "search_source",
             "result": {"rows": [{"path": "SafeOrderService.java"}]}},
        ]},
        {"items": [{"tool": "read_file",
                    "result": {"rows": [demo_row("SafeOrderService.java")]}}]},
    ]
    original = demo_row()
    original["content"] = "import com.example.SafeOrderService;\nclass Controller {}"
    selected = {"read-1": original}
    assert _prefetch_candidate_dependencies(tools, selected) == 1
    assert "read-2" in selected
    assert tools.call.call_count == 2


def test_runtime_sensitive_review_prefetches_manifest_and_approved_config():
    def row(path, evidence_id):
        value = demo_row()
        value.update(relative_path=path, chunk_id=evidence_id, evidence_id=evidence_id,
                     content="context", content_sha256=evidence_id)
        return value

    tools = MagicMock()
    tools.call.side_effect = [
        {"rows": [row("pom.xml", "pom")]},
        *[ValueError("not present") for _ in range(5)],
        {"rows": [row("src/main/resources/application.yml", "config")]},
    ]
    selected = {"read-1": row("PreferenceService.java", "read-1")}
    detail = {"ruleId": "unsafe-deserialization", "summary": "依赖JDK与classpath gadget"}
    reads = _prefetch_candidate_context(
        tools, selected, detail,
        {"approved_config_paths": ["src/main/resources/application.yml"]},
    )
    assert reads == 2
    assert {row["relative_path"] for row in selected.values()} == {
        "PreferenceService.java", "pom.xml", "src/main/resources/application.yml",
    }


def test_plain_dataflow_review_does_not_prefetch_global_context():
    tools = MagicMock()
    assert _prefetch_candidate_context(
        tools, {"read-1": demo_row()}, {"ruleId": "sql-injection"},
        {"approved_config_paths": ["application.yml"]},
    ) == 0
    tools.call.assert_not_called()


def test_approved_paths_alone_do_not_invalidate_review_identity():
    model = MagicMock()
    model.next_action.return_value = {
        "investigation_id": "i", "outcome": "inconclusive", "assessment": "证据不足",
        "counterevidence": "无", "limitations": ["静态"], "evidence_ids": ["read-1"],
    }
    evidence = {"read-1": demo_row()}
    investigation = {"id": "i", "question": "q", "evidence_ids": ["read-1"]}
    boundary = {"entry": "api", "asset": "data", "evidence_ids": ["read-1"]}
    plain = review_packet(model, investigation, boundary, evidence,
                          user_context={"security_context": "remote"})
    approved = review_packet(
        model, investigation, boundary, evidence,
        user_context={"security_context": "remote", "approved_config_paths": ["application.yml"]},
    )
    assert approved["input_sha256"] == plain["input_sha256"]


def test_baseline_provenance_links_do_not_invalidate_review_identity():
    model = MagicMock()
    model.next_action.return_value = {
        "investigation_id": "i", "outcome": "inconclusive", "assessment": "证据不足",
        "counterevidence": "无", "limitations": ["静态"], "evidence_ids": ["read-1"],
    }
    evidence = {"read-1": demo_row()}
    boundary = {"entry": "api", "asset": "data", "evidence_ids": ["read-1"]}
    base = {"id": "i", "question": "q", "evidence_ids": ["read-1"],
            "baseline_question_ids": []}
    first = review_packet(model, base, boundary, evidence)
    linked = review_packet(model, {**base, "baseline_question_ids": ["baseline-1"]},
                           boundary, evidence)
    assert linked["input_sha256"] == first["input_sha256"]


def test_review_contract_rejects_process_placeholder():
    evidence = {"read-1": demo_row()}
    with pytest.raises(ModelOutputError, match="过程性占位"):
        InvestigationReview.parse({
            "investigation_id": "i", "outcome": "inconclusive",
            "assessment": "正在收集证据，稍后提交正式结论。",
            "counterevidence": "尚未形成反证", "limitations": ["正式提交时替换"],
            "evidence_ids": ["read-1"],
        }, [{"id": "i"}], evidence)


def test_review_with_additional_evidence_is_reused_after_restore():
    """补证随 checkpoint 恢复后，指纹完整匹配应允许复用。"""
    model, tools = MagicMock(), MagicMock()
    model.next_action.side_effect = [
        {"tool": "read_file", "arguments": {"path": "SafeOrderService.java"}},
        {"investigation_id": "i", "outcome": "inconclusive", "assessment": "证据不足",
         "counterevidence": "上游未知", "limitations": ["静态检查"], "evidence_ids": ["read-2"]},
    ]
    tools.call.return_value = {"rows": [demo_row("SafeOrderService.java")]}
    evidence = {"read-1": demo_row()}
    review = review_packet(model, {"id": "i", "question": "q", "evidence_ids": ["read-1"]},
        {"entry": "fetch", "asset": "order", "evidence_ids": ["read-1"]}, evidence,
        tools=tools, user_context={"scope": "a"},
        on_tool=lambda action, result: [
            evidence.update({row["evidence_id"]: row})
            for row in result.get("rows", [])
        ] if action.tool in {"read_chunk", "read_file"} else None,
    )
    restored = deepcopy(evidence)  # checkpoint 恢复后的完整 evidence
    assert review_evidence_matches(review, restored)
    assert review["method"] == "independent_context_packet_review"
    assert review["input_identity_version"] == 1
    model.reset_mock()
    reused = review_packet(model, {"id": "i", "question": "q", "evidence_ids": ["read-1"]},
        {"entry": "fetch", "asset": "order", "evidence_ids": ["read-1"]}, restored,
        tools=tools, user_context={"scope": "a"}, previous_reviews=[review])
    assert reused["reused"] is True
    model.next_action.assert_not_called()


def test_matching_input_but_changed_detail_is_not_reused():
    model = MagicMock()
    model.next_action.return_value = {
        "investigation_id": "i", "outcome": "supported", "assessment": "合成复核",
        "counterevidence": "上游未提供", "limitations": ["静态检查"], "evidence_ids": ["read-1"],
    }
    investigation = {"id": "i", "question": "q", "evidence_ids": ["read-1"]}
    boundary = {"entry": "fetch", "asset": "order", "evidence_ids": ["read-1"]}
    evidence = {"read-1": demo_row()}
    detail = candidate_detail()
    review = review_packet(model, investigation, boundary, evidence, detail=detail,
                           user_context={"scope": "a"})
    model.reset_mock()
    changed_detail = deepcopy(detail)
    changed_detail["title"] = "改动后的候选标题"
    review_packet(model, investigation, boundary, evidence, detail=changed_detail,
                  user_context={"scope": "a"}, previous_reviews=[review])
    model.next_action.assert_called_once()


def test_matching_review_skips_model_but_changed_context_does_not():
    model = MagicMock()
    model.next_action.return_value = {
        "investigation_id": "i", "outcome": "inconclusive", "assessment": "证据不足",
        "counterevidence": "上游未知", "limitations": ["静态检查"], "evidence_ids": ["read-1"],
    }
    investigation = {"id": "i", "question": "q", "evidence_ids": ["read-1"]}
    boundary = {"entry": "fetch", "asset": "order", "evidence_ids": ["read-1"]}
    evidence = {"read-1": demo_row()}
    original = review_packet(model, investigation, boundary, evidence, user_context={"scope": "a"})
    saved = deepcopy(original)
    model.reset_mock()
    reused = review_packet(model, investigation, boundary, evidence, user_context={"scope": "a"},
                           previous_reviews=[original])
    assert reused["reused"] is True
    model.next_action.assert_not_called()
    assert original == saved
    review_packet(model, investigation, boundary, evidence, user_context={"scope": "b"},
                  previous_reviews=[original])
    model.next_action.assert_called_once()
    broken = deepcopy(original)
    broken["outcome"] = "invalid"
    model.reset_mock()
    result = review_packet(model, investigation, boundary, evidence, user_context={"scope": "a"},
                           previous_reviews=[broken])
    model.next_action.assert_called_once()
    assert not result.get("reused", False)
