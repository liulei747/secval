"""仅用合成代码验收本机正式Web接口，不读取模型密钥。"""

import argparse
import io
import json
import re
import zipfile
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from uuid import uuid4

from benchmarks.audit_quality.cases import CASES, model_input

BASE_URL = "http://127.0.0.1:8000"


def request(path, data=None, content_type="application/json"):
    if isinstance(data, dict):
        data = json.dumps(data, ensure_ascii=False).encode("utf-8")
    try:
        with urlopen(Request(BASE_URL + path, data=data,
                             headers={"Content-Type": content_type}), timeout=600) as response:
            return json.load(response)
    except HTTPError as error:
        raise RuntimeError(f"本机Web验收HTTP {error.code}，未自动重试") from None
    except (URLError, OSError):
        raise RuntimeError("本机Web请求失败，未自动重试；请先检查已保存进度") from None


def archive_bytes(case):
    """压缩包仅含合成源码，绝不包含expected答案字段。"""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for path, content in model_input(case)["files"].items():
            archive.writestr(path, content.encode("utf-8"))
    return buffer.getvalue()


def save(directory, name, value):
    (directory / name).write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")


def start(case):
    if any(task["status"] in {"queued", "running"} or task.get("execution_active") for task in request("/api/audits")):
        raise RuntimeError("正式API已有审计任务，停止创建测试")
    run_id = uuid4().hex
    repository = "secval-web-check-" + run_id
    directory = Path("data/web-audit-checks") / run_id
    directory.mkdir(parents=True, exist_ok=False)
    manifest = {"case": case["id"], "repository_id": repository, "snapshot_id": run_id,
                "repository_directory": repository, "stage": "upload"}
    save(directory, "manifest.json", manifest)
    boundary = "secval-" + uuid4().hex
    body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"repository_directory\"\r\n\r\n"
            f"{repository}\r\n--{boundary}\r\n"
            'Content-Disposition: form-data; name="zip_file"; filename="synthetic.zip"\r\n'
            'Content-Type: application/zip\r\n\r\n').encode()
    body += archive_bytes(case) + f"\r\n--{boundary}--\r\n".encode()
    uploaded = request("/api/repositories/upload-zip", body, "multipart/form-data; boundary=" + boundary)
    if uploaded["repository_path"] != repository or uploaded["replaced_existing"]:
        raise RuntimeError("上传结果与独立测试目录不一致，停止")
    manifest["stage"] = "index"
    save(directory, "manifest.json", manifest)
    indexed = request("/api/repositories/index", {
        "repository_id": repository, "repository_name": "合成Web验收",
        "repository_path": repository, "snapshot_id": run_id, "version": "synthetic",
    })
    manifest["index"] = {key: indexed[key] for key in ("index_run_id", "successful_files", "failed_files",
                                                       "saved_chunks", "saved_vectors", "deleted_chunks")}
    manifest["stage"] = "search"
    save(directory, "manifest.json", manifest)
    if indexed["failed_files"] or not indexed["saved_chunks"] or indexed["deleted_chunks"]:
        raise RuntimeError("合成索引结果未满足验收条件，停止")
    searched = request("/api/search", {"text": "OrderService fetch ownerUserId",
        "repository_ids": [repository], "snapshot_ids": [run_id], "top_k": 3})
    if not searched["results"] or any(row["repository_id"] != repository or row["snapshot_id"] != run_id
                                      for row in searched["results"]):
        raise RuntimeError("混合搜索未返回合成范围内结果，停止")
    manifest["search_result_count"] = len(searched["results"])
    manifest["stage"] = "create_audit"
    save(directory, "manifest.json", manifest)
    inputs = model_input(case)
    task = request("/api/audits", {"objective": inputs["objective"], "security_context": inputs["security_context"],
        "repository_id": repository, "snapshot_id": run_id, "allow_remote_code": True,
        "independent_baseline": True, "max_steps": 40, "max_seconds": 1800})
    manifest.update(stage="audit_started", task_id=task["id"])
    save(directory, "manifest.json", manifest)
    return {"directory": str(directory.resolve()), **manifest}


def collect(path, task_id=None):
    directory = Path(path).resolve()
    if directory.parent != Path("data/web-audit-checks").resolve() or not re.fullmatch("[a-f0-9]{32}", directory.name):
        raise ValueError("仅允许读取本脚本生成的Web验收目录")
    manifest = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
    task_id = task_id or manifest["task_id"]
    if not re.fullmatch("[a-f0-9]{32}", task_id):
        raise ValueError("测试任务编号不合法")
    task = request("/api/audits/" + task_id)
    if (task["repository_id"], task["snapshot_id"]) != (manifest["repository_id"], manifest["snapshot_id"]):
        raise ValueError("任务不属于此合成验收")
    summary = {key: task.get(key) for key in ("id", "status", "phase", "model_calls", "stop_reason")}
    if task["status"] not in {"queued", "running"}:
        report = request(f"/api/audits/{task_id}/report")
        result_directory = directory
        if task_id != manifest["task_id"]:
            result_directory = directory / "continuations" / task_id
            result_directory.mkdir(parents=True, exist_ok=True)
        save(result_directory, "report.json", report)
        summary.update(findings=len(report["findings"]), independent_reviews=len(report["independentReviews"]),
                       quality_passed=None, note="需要核对证据与结论，不能以返回报告代替质量验收")
        save(result_directory, "summary.json", summary)
    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", choices=[case["id"] for case in CASES], default="case-a")
    parser.add_argument("--allow-model-calls", action="store_true")
    parser.add_argument("--collect")
    parser.add_argument("--task", help="收集同一合成仓库的续跑任务，不覆盖父报告")
    args = parser.parse_args()
    if args.collect:
        result = collect(args.collect, args.task)
    else:
        if args.task:
            parser.error("--task必须与--collect一起使用")
        if not args.allow_model_calls:
            parser.error("上传索引、混合搜索和审计可能调用远程模型，必须显式允许")
        result = start(next(case for case in CASES if case["id"] == args.case))
    print(json.dumps(result, ensure_ascii=False))
