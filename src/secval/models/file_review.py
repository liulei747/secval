"""整文件安全审阅声明，必须有本版本完整阅读证据；仍需语义复核。"""

from secval.models.audit_contracts import ModelOutputError
from secval.models.read_coverage import read_coverage


def parse_file_review(raw, evidence):
    if not isinstance(raw, dict) or set(raw) != {"file_id", "assessment", "controls_checked", "unknowns"}:
        raise ModelOutputError("文件审阅需要file_id、assessment、controls_checked、unknowns")
    for key in ("file_id", "assessment"):
        if not isinstance(raw[key], str) or not 1 <= len(raw[key].strip()) <= 4000:
            raise ModelOutputError("文件审阅描述不合法")
    for key in ("controls_checked", "unknowns"):
        values = raw[key]
        if (not isinstance(values, list) or len(values) > 20 or (key == "controls_checked" and not values)
                or any(not isinstance(v, str) or not 1 <= len(v.strip()) <= 2000 for v in values)):
            raise ModelOutputError("检查控制和未知项必须为有界字符串数组")
    candidates = [item for item in read_coverage(evidence)["objects"] if item["object_id"] == raw["file_id"]
                  and item["kind"] == "file" and item["fully_read"]]
    if len(candidates) != 1:
        raise ModelOutputError("只能登记当前快照已经完整读取的文件，代码块不能代替整文件")
    item = candidates[0]
    return {**raw, "path": item["path"], "source_snapshot_id": item["source_snapshot_id"],
            "content_sha256": item["content_sha256"], "status": "partial" if raw["unknowns"] else "reviewed_static",
            "semantically_verified": False}
