"""模型输出契约；严格拒绝歧义动作，验证错误不回显模型原文。"""

from dataclasses import dataclass
from typing import Any

from secval.models.source_range import validate_line_range


class ModelOutputError(ValueError):
    """可纠正的格式问题。"""


class ModelRequestError(ValueError):
    """不可自动重试的请求故障。"""


@dataclass(frozen=True)
class CodeEvidence:
    id: str
    label: str
    path: str
    startLine: int
    endLine: int
    code: str
    explanation: str
    repository_id: str
    snapshot_id: str
    content_sha256: str
    truncated: bool

    @classmethod
    def from_read(cls, row):
        # 证据正文与位置由工具提供，不接受模型重新拼写源码。
        required = (
            "chunk_id",
            "relative_path",
            "repository_id",
            "snapshot_id",
            "content_sha256",
        )
        if not isinstance(row, dict) or not all(text(row.get(k)) for k in required):
            raise ValueError("证据来源字段不完整")
        if not isinstance(row.get("content"), str) or not row["content"]:
            raise ValueError("证据正文不能为空")
        start, end = row.get("start_line"), row.get("end_line")
        if type(start) is not int or type(end) is not int or start < 1 or end < start:
            raise ValueError("证据行号不合法")
        if type(row.get("truncated")) is not bool:
            raise ValueError("证据必须声明截断状态")
        return cls(
            row.get("evidence_id", row["chunk_id"]),
            row.get("symbol_name") or row["relative_path"],
            row["relative_path"],
            start,
            end,
            row["content"],
            "工具读取的源码证据；此记录仅证明读取来源，不自动支持漏洞结论。",
            row["repository_id"],
            row["snapshot_id"],
            row["content_sha256"],
            row["truncated"],
        )


def text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


@dataclass(frozen=True)
class ToolAction:
    tool: str
    arguments: dict

    @classmethod
    def parse(cls, raw):
        allowed = {
            "audit_progress": {"offset"},
            "record_file_review": {"file_id", "assessment", "controls_checked", "unknowns"},
            "record_finding_detail": {"investigation_id", "title", "summary", "rootCause", "attackPath",
                                      "severity", "confidence", "remediation", "remediationTests", "preventiveControls", "evidenceNotes",
                                      "ruleId", "taxonomy", "root_control"},
            "record_threat_model": {"summary", "assets", "trustBoundaries", "attackerCapabilities",
                                    "securityObjectives", "assumptions"},
            "review_investigation": {"investigation_id", "outcome", "assessment",
                                     "counterevidence", "limitations", "evidence_ids"},
            "record_investigation": {"boundary_id", "question", "control_to_check",
                                     "counterevidence", "next_check", "unknowns", "evidence_ids", "baseline_question_ids"},
            "record_boundary": {"entry", "attacker_control", "asset", "trust_transition",
                                "expected_control", "observed_control", "unknowns", "evidence_ids"},
            "list_files": {"offset"},
            "read_file": {"path", "char_offset", "start_line", "end_line"},
            "list_chunks": {"offset"},
            "search_text": {"text", "offset"},
            "search_source": {"text", "offset"},
            "find_symbol": {"text", "offset"},
            "read_chunk": {"chunk_id", "char_offset", "start_line", "end_line"},
        }
        if not isinstance(raw, dict) or set(raw) != {"tool", "arguments"}:
            raise ModelOutputError("动作必须仅包含tool和arguments，不能同时提交报告")
        name, args = raw["tool"], raw["arguments"]
        if (
            not isinstance(name, str)
            or name not in allowed
            or not isinstance(args, dict)
        ):
            raise ModelOutputError("工具名称或参数对象不合法")
        if set(args) - allowed[name]:
            raise ModelOutputError("工具包含未允许参数")
        offset = args.get("offset", 0)
        char_offset = args.get("char_offset", 0)
        if type(char_offset) is not int or char_offset < 0:
            raise ModelOutputError("char_offset必须为非负整数")
        if type(offset) is not int or not 0 <= offset <= 9980:
            raise ModelOutputError("offset必须是0到9980的整数")
        if name in ("find_symbol", "search_text", "search_source") and (
            not text(args.get("text")) or len(args["text"]) > 500
        ):
            raise ModelOutputError("text必须是1到500字符的非空文本")
        if name == "read_chunk" and (
            not text(args.get("chunk_id")) or len(args["chunk_id"]) > 200
        ):
            raise ModelOutputError("chunk_id必须是1到200字符的非空文本")
        if name == "read_file" and (
            not text(args.get("path")) or len(args["path"]) > 1000
        ):
            raise ModelOutputError("path必须是1到1000字符的非空文本")
        try:
            validate_line_range(args)
        except ValueError as error:
            raise ModelOutputError(str(error)) from None
        return cls(name, args)


@dataclass(frozen=True)
class InvestigationReport:
    summary: str
    hypotheses: list[dict]
    unknowns: list[str]

    @classmethod
    def parse(cls, raw, evidence):
        if not isinstance(raw, dict) or set(raw) != {
            "summary",
            "hypotheses",
            "unknowns",
        }:
            raise ModelOutputError("报告仅允许summary、hypotheses和unknowns")
        if not text(raw["summary"]):
            raise ModelOutputError("summary不能为空")
        unknowns = raw["unknowns"]
        if (
            not isinstance(unknowns, list)
            or not unknowns
            or not all(map(text, unknowns))
        ):
            raise ModelOutputError("unknowns必须为非空字符串数组")
        hypotheses = raw["hypotheses"]
        if not isinstance(hypotheses, list):
            raise ModelOutputError("hypotheses必须为数组")
        for item in hypotheses:
            if not isinstance(item, dict) or set(item) != {
                "claim",
                "counterevidence",
                "unknowns",
                "evidence_ids",
            }:
                raise ModelOutputError("候选问题字段不完整或包含未知字段")
            if not all(text(item[k]) for k in ("claim", "counterevidence", "unknowns")):
                raise ModelOutputError("候选问题、反证和未知项不能为空")
            ids = item["evidence_ids"]
            if (
                not isinstance(ids, list)
                or not ids
                or not all(map(text, ids))
                or len(set(ids)) != len(ids)
                or any(i not in evidence for i in ids)
            ):
                raise ModelOutputError("引用必须是不重复的已读证据ID数组")
        return cls(raw["summary"], hypotheses, unknowns)
