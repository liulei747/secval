"""任务级 token 汇总：缺失字段不计 0，各请求用量正确累计。"""

from secval.services.audit_report import export_audit_report


def test_token_usage_sums_only_reported_values():
    task = {
        "id": "t", "status": "needs_review", "phase": "reporting",
        "model_requests": [
            {"call": 1, "prompt_tokens": 100, "completion_tokens": 20, "total_tokens": 120},
            {"call": 2, "total_tokens": 50},
            {"call": 3},
        ],
    }
    usage = export_audit_report(task)["tokenUsage"]
    assert usage["promptTokens"] == 100
    assert usage["completionTokens"] == 20
    assert usage["totalTokens"] == 170
    assert usage["requestsCountedBySupplier"] == 2
    assert usage["requestsTotal"] == 3


def test_token_usage_empty_requests():
    task = {"id": "t", "model_requests": []}
    usage = export_audit_report(task)["tokenUsage"]
    assert usage["totalTokens"] == 0
    assert usage["requestsTotal"] == 0
