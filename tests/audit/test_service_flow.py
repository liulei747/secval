"""脚本模型只验证编排与证据约束，不代表真实模型审计质量。"""

import hashlib
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import MagicMock
import pytest

from secval.infrastructure.audit.sqlite_audit_store import AuditStore
from secval.models.audit import AuditTaskInput
from secval.models.audit_contracts import ModelOutputError, ModelRequestError
from secval.services.audit_service import AuditService


def candidate_detail():
    refs = ["read-1"]
    return {
        "investigation_id": "investigation-1", "title": "合成候选", "summary": "合成控制缺口",
        "ruleId": "test-authorization", "taxonomy": {"category": "authorization", "cwe": ["CWE-862"]},
        "root_control": "read-1", "rootCause": {"summary": "合成根因", "evidenceRefs": refs},
        "attackPath": {
            "summary": "合成路径", "evidenceRefs": refs,
            "dataflow": {"summary": "数据流", "source": "参数", "transformations": [],
                         "sink": "返回", "outcome": "读取", "evidenceRefs": refs},
            "reachability": {"summary": "可达性", "attacker": "普通用户", "entrypoint": "fetch",
                             "preconditions": [], "outcome": "读取", "evidenceRefs": refs},
            "impact": {"level": "medium", "rationale": "合成影响"},
            "likelihood": {"level": "high", "rationale": "合成前提"}, "limitations": ["静态测试"],
        },
        "severity": {"level": "medium", "rationale": "合成评级"},
        "confidence": {"level": "medium", "rationale": "合成证据"},
        "remediation": "加入控制", "remediationTests": ["验证隔离"], "preventiveControls": ["复核"],
        "evidenceNotes": [{"evidence_id": "read-1", "role": "root_control", "explanation": "合成根因锚点"}],
    }


@pytest.mark.parametrize("review_fails", [False, True])
@pytest.mark.parametrize("spaced_errors", [False, True])
def test_service_reaches_independent_validation_and_report(tmp_path, review_fails, spaced_errors):
    source = "class OrderService { Object fetch(long id) { return null; } }"
    digest = hashlib.sha256(source.encode()).hexdigest()
    row = {"chunk_id": "file-1", "evidence_id": "read-1", "repository_id": "repo",
           "snapshot_id": "snap", "relative_path": "OrderService.java", "content": source,
           "content_sha256": digest, "start_line": 1, "end_line": 1, "truncated": False}
    tools = MagicMock()

    def tool_call(name, arguments):
        if name == "list_chunks":
            return {"total": 1, "rows": []}
        if name == "scope_info":
            return {"repository_id": "repo", "snapshot_id": "snap", "source_snapshot_id": "source",
                    "index_run_id": "run", "_inventory": [{"path": "OrderService.java",
                    "status": "captured", "digest": digest}]}
        if name == "read_file":
            return {"rows": [row]}
        raise AssertionError("unexpected tool")

    tools.call.side_effect = tool_call
    review = {"investigation_id": "investigation-1", "outcome": "supported", "assessment": "合成判断",
              "counterevidence": "合成反证", "limitations": ["仅测试编排"], "evidence_ids": ["read-1"]}
    model = MagicMock()
    actions = [
        {"tool": "read_file", "arguments": {"path": "OrderService.java"}},
        {"questions": [{"question": "是否有控制", "evidence_ids": ["read-1"], "unknowns": ["待验证"]}],
         "unknowns": ["静态测试"]},
        {"tool": "record_boundary", "arguments": {"entry": "fetch", "attacker_control": "id",
         "asset": "订单", "trust_transition": "用户到订单", "expected_control": "归属检查",
         "observed_control": "合成观察", "unknowns": ["待复核"], "evidence_ids": ["read-1"]}},
        {"tool": "record_investigation", "arguments": {"boundary_id": "boundary-1", "question": "控制问题",
         "control_to_check": "归属", "counterevidence": "待检查", "next_check": "复核", "unknowns": ["静态"],
         "evidence_ids": ["read-1"], "baseline_question_ids": ["baseline-1"]}},
        {"tool": "review_investigation", "arguments": review},
        {"tool": "record_finding_detail", "arguments": candidate_detail()},
        {"report": {"summary": "合成报告", "hypotheses": [], "unknowns": ["静态测试"]}},
        ModelRequestError("合成请求超时") if review_fails else review,
    ]
    responses = []
    for index, action in enumerate(actions):
        if spaced_errors and index in {2, 4, 6}:
            responses.append(ModelOutputError("合成间隔格式错误"))
        responses.append(action)
    model.next_action.side_effect = responses
    service = AuditService(AuditStore(tmp_path / "tasks.sqlite3"), ThreadPoolExecutor(max_workers=1),
                           lambda: model, lambda repo, snap: tools)
    try:
        task = service.create(AuditTaskInput(objective="合成完整流程检查", repository_id="repo",
                                            snapshot_id="snap", allow_remote_code=True, max_steps=30))
        service.future.result(timeout=10)
        report = service.report(task["id"])
        assert report["status"] == "needs_review"
        assert len(report["findings"]) == (0 if review_fails else 1)
        assert len(report["independentReviews"]) == 1
        if review_fails:
            assert report["independentReviews"][0]["outcome"] == "inconclusive"
            assert report["coverage"]["deferred"]
        else:
            assert report["findings"][0]["status"] == "static_supported_needs_review"
        assert report["coverage"]["complete"] is False
        assert report["continuation"]["currentModelCalls"] == (11 if spaced_errors else 8)
        tools.close.assert_called_once()
        independent_messages = model.next_action.call_args_list[-1].args[0]
        assert len(independent_messages) == 2
        assert "静态证据复核员" in independent_messages[0]["content"]
    finally:
        service.close()
