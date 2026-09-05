"""合成项目的真实Agent链路检查；必须显式选择模型凭据来源。"""

import argparse
import json
import os
import re
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from time import monotonic
from uuid import uuid4

from opensearchpy import OpenSearch

from benchmarks.audit_quality.cases import CASES, model_input
from secval.config.search_settings import load_search_settings
from secval.infrastructure.audit.api_audit_model import AuditModel
from secval.infrastructure.audit.index_evidence_tools import EvidenceTools
from secval.infrastructure.audit.source_snapshot_store import SourceSnapshotStore
from secval.infrastructure.audit.sqlite_audit_store import AuditStore
from secval.infrastructure.opensearch.code_index import CODE_INDEX_BODY
from secval.models.audit import AuditTaskInput
from secval.models.audit_contracts import ModelOutputError, ModelRequestError
from secval.services.audit_service import AuditService


class CountedModel:
    """独立硬性请求计数；网络失败也占一次，不做重试。"""

    def __init__(self, model, limit):
        self.model = model
        self.limit = limit
        self.calls = 0
        self.records = []

    def next_action(self, messages):
        if self.calls >= self.limit:
            raise ModelRequestError("验收请求额度已用完")
        self.calls += 1
        started = monotonic()
        record = {"call": self.calls, "status": "started",
                  "input_characters": sum(len(message["content"]) for message in messages)}
        print(json.dumps({"event": "model_request", "call": self.calls}), flush=True)
        try:
            result = self.model.next_action(messages)
            record["status"] = "returned"
            return result
        except ModelOutputError as error:
            record.update(status="invalid_output", code=error.code)
            raise
        except ModelRequestError:
            record["status"] = "request_failed"
            raise
        finally:
            record["seconds"] = round(monotonic() - started, 2)
            info = getattr(self.model, "last_response_info", {})
            if isinstance(info, dict):
                record["response_counts"] = dict(info)
            self.records.append(record)
            print(json.dumps({"event": "model_request_ended", "call": self.calls,
                              "seconds": round(monotonic() - started, 2)}), flush=True)


def run_check(model, case, *, max_calls=9, max_seconds=600, output_root="data/audit-checks"):
    """仅建立合成全文块索引，不调用向量模型，也不验证生产索引流水线。"""
    if type(max_calls) is not int or not 3 <= max_calls <= 60:
        raise ValueError("验收调用上限必须为3到60")
    if type(max_seconds) is not int or not 30 <= max_seconds <= 3600:
        raise ValueError("验收任务时长必须为30到3600秒")
    run_id = uuid4().hex
    index = "secval-agent-check-" + run_id
    output = Path(output_root) / run_id
    output.mkdir(parents=True, exist_ok=False)
    root = output / "source"
    root.mkdir()
    inputs = model_input(case)
    for relative, content in inputs["files"].items():
        destination = (root / relative).resolve()
        if not destination.is_relative_to(root.resolve()):
            raise ValueError("合成样例路径越界")
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(content.encode("utf-8"))
    source_store = SourceSnapshotStore(str(output / "sources.sqlite3"))
    source_id = source_store.capture(root, run_id, "synthetic")
    client = OpenSearch(hosts=[{"host": "127.0.0.1", "port": 9200}], max_retries=0)
    counted = CountedModel(model, max_calls)
    service = None
    created = False
    try:
        client.indices.create(index=index, body=CODE_INDEX_BODY)
        created = True
        for number, (relative, content) in enumerate(inputs["files"].items()):
            if source_store.read(source_id, relative) != content:
                raise ValueError("合成源码快照与待索引正文不一致，停止验收")
            chunk_id = f"{run_id}-{number}"
            client.index(index=index, id=chunk_id, body={
                "chunk_id": chunk_id, "repository_id": run_id, "snapshot_id": "synthetic",
                "index_run_id": run_id, "relative_path": relative, "content": content,
                "start_line": 1, "end_line": len(content.splitlines()), "language": "java",
            })
        client.indices.refresh(index=index)
        source_store.bind(source_id, run_id, "synthetic", run_id)
        service = AuditService(
            AuditStore(output / "tasks.sqlite3"), ThreadPoolExecutor(max_workers=1),
            lambda: counted,
            lambda repo, snapshot: EvidenceTools(client, repo, snapshot, source_store, index_name=index),
        )
        task = service.create(AuditTaskInput(
            objective=inputs["objective"], repository_id=run_id, snapshot_id="synthetic",
            security_context=inputs["security_context"], allow_remote_code=True,
            max_steps=max_calls, max_seconds=max_seconds,
        ))
        service.future.result()
        return save_result(service, task, case, counted, output)
    finally:
        if service is not None:
            service.close()
        try:
            if created:
                # 只清理本函数生成的精确索引名，绝不使用通配符。
                client.indices.delete(index=index)
        finally:
            client.close()


def save_result(service, task, case, counted, output):
    report = service.report(task["id"])
    saved_task = service.get(task["id"])
    (output / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    summary = {"case": case["id"], "status": report["status"], "calls": counted.calls,
               "evidence_count": len(report["codeEvidence"]), "findings": len(report["findings"]),
               "independent_reviews": len(report["independentReviews"]),
               "expected": case["expected"]["outcome"], "quality_passed": None,
               "note": "需人工核对；预算耗尽或空报告不等于反例通过", "output": str(output.resolve()),
               "stop_reason": report["stopReason"], "error": report["error"],
               "current_format_errors": sum(1 for event in saved_task.get("events", [])
                                            if event.get("task_id") == task["id"]
                                            and event.get("type") == "format_error"),
               "candidate_details": len(saved_task.get("finding_detail_history", [])),
               "investigation_outcomes": [row["status"] for row in saved_task.get("investigations", [])],
               "request_seconds": round(sum(row["seconds"] for row in counted.records), 2)}
    (output / "requests.json").write_text(json.dumps(counted.records, indent=2), encoding="utf-8")
    (output / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    return summary


def resume_check(model, directory, *, max_calls=30, max_seconds=1800, resume_task=None):
    """只恢复本脚本的合成产物；不重采源码，不覆盖父任务或正式索引。"""
    output = Path(directory).resolve()
    allowed_root = Path("data/audit-checks").resolve()
    if output.parent != allowed_root or not re.fullmatch("[a-f0-9]{32}", output.name):
        raise ValueError("仅允许续跑data/audit-checks下的合成验收目录")
    summary = json.loads((output / "summary.json").read_text(encoding="utf-8"))
    case = next(case for case in CASES if case["id"] == summary["case"])
    inputs = model_input(case)
    saved_report = json.loads((output / "report.json").read_text(encoding="utf-8"))
    store = AuditStore(output / "tasks.sqlite3")
    parent = store.get(resume_task or saved_report["taskId"])
    source_store = SourceSnapshotStore(str(output / "sources.sqlite3"))
    run_id = output.name
    source_id = source_store.resolve_binding(run_id, "synthetic", run_id)
    if (source_id is None or parent["repository_id"] != run_id or parent["snapshot_id"] != "synthetic"
            or parent["objective"] != inputs["objective"] or parent["security_context"] != inputs["security_context"]):
        raise ValueError("验收资料或源码绑定不一致")
    inventory = source_store.inventory(source_id)
    if {row["path"] for row in inventory} != set(inputs["files"]):
        raise ValueError("合成文件清单不一致")
    for relative, content in inputs["files"].items():
        if source_store.read(source_id, relative) != content:
            raise ValueError("合成正文不一致，禁止续跑")
    # 先校验预算与授权，避免创建测试索引后才发现配置不合法。
    AuditTaskInput(objective=inputs["objective"], repository_id=run_id, snapshot_id="synthetic",
                   allow_remote_code=True, max_steps=max_calls, max_seconds=max_seconds)
    index = "secval-agent-check-" + run_id
    client = OpenSearch(hosts=[{"host": "127.0.0.1", "port": 9200}], max_retries=0)
    counted = CountedModel(model, max_calls)
    service = None
    created = False
    try:
        client.indices.create(index=index, body=CODE_INDEX_BODY)
        created = True
        for number, (relative, content) in enumerate(inputs["files"].items()):
            chunk_id = f"{run_id}-{number}"
            client.index(index=index, id=chunk_id, body={"chunk_id": chunk_id,
                "repository_id": run_id, "snapshot_id": "synthetic", "index_run_id": run_id,
                "relative_path": relative, "content": content, "start_line": 1,
                "end_line": len(content.splitlines()), "language": "java"})
        client.indices.refresh(index=index)
        service = AuditService(store, ThreadPoolExecutor(max_workers=1), lambda: counted,
            lambda repo, snap: EvidenceTools(client, repo, snap, source_store, index_name=index))
        task = service.resume(parent["id"], max_steps=max_calls, max_seconds=max_seconds, allow_remote_code=True)
        service.future.result()
        result_directory = output / "continuations" / task["id"]
        result_directory.mkdir(parents=True, exist_ok=False)
        return save_result(service, task, case, counted, result_directory)
    finally:
        if service is not None:
            service.close()
        try:
            if created:
                client.indices.delete(index=index)
        finally:
            client.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", choices=[case["id"] for case in CASES], default="case-a")
    parser.add_argument("--max-calls", type=int, default=30)
    parser.add_argument("--timeout-seconds", type=int, default=120)
    parser.add_argument("--max-seconds", type=int, default=600)
    parser.add_argument("--thinking", choices=["enabled", "disabled"], default=None)
    parser.add_argument("--resume", default=None)
    parser.add_argument("--resume-task", default=None, help="同一合成验收数据库中的检查点任务ID")
    parser.add_argument("--max-output-tokens", type=int, default=8192)
    parser.add_argument("--use-search-model", action="store_true")
    args = parser.parse_args()
    if args.use_search_model:
        settings = load_search_settings("config/search.docker.yaml")
        url = os.getenv("SECVAL_EMBEDDING_API_URL", "").rstrip("/").removesuffix("/embeddings")
        key = os.getenv("SECVAL_EMBEDDING_API_KEY", "")
        name = settings.reranker.model_name
    else:
        url = os.getenv("SECVAL_AUDIT_API_URL", "")
        key = os.getenv("SECVAL_AUDIT_API_KEY", "")
        name = os.getenv("SECVAL_AUDIT_MODEL", "glm-5.3-flash")
    if args.resume_task is not None and args.resume is None:
        parser.error("--resume-task必须与--resume一起使用")
    model = AuditModel(url, key, name, timeout_seconds=args.timeout_seconds, thinking=args.thinking,
                       max_output_tokens=args.max_output_tokens)
    if args.resume is not None:
        print(json.dumps(resume_check(model, args.resume, max_calls=args.max_calls,
                                     max_seconds=args.max_seconds, resume_task=args.resume_task), ensure_ascii=False))
        return
    case = next(case for case in CASES if case["id"] == args.case)
    print(json.dumps(run_check(model, case, max_calls=args.max_calls, max_seconds=args.max_seconds), ensure_ascii=False))


if __name__ == "__main__":
    main()
