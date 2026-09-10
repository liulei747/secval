"""Structured, evidence-bound candidate records shared by specialized analyzers."""

import hashlib
import json
from dataclasses import dataclass
from enum import StrEnum

from secval.facts import SourceLocation


class CandidateKind(StrEnum):
    TAINT_FLOW = "taint_flow"
    UNKNOWN_EFFECT = "unknown_effect"
    MISSING_GUARD = "missing_guard"
    AUTHORIZATION = "authorization"
    CONFIGURATION = "configuration"
    STRUCTURAL = "structural"
    DEPENDENCY = "dependency"
    STATE_MACHINE = "state_machine"
    RACE_TRANSACTION = "race_transaction"


class CandidateStatus(StrEnum):
    NEEDS_REVIEW = "NEEDS_REVIEW"


def candidate_identity(rule_id, snapshot_id, entry_node_id, operation_node_id,
                       root_cause_node_id, resource_node_id=None):
    resource_node_id = resource_node_id or root_cause_node_id
    values = (rule_id, snapshot_id, entry_node_id, operation_node_id,
              resource_node_id, root_cause_node_id)
    if any(not isinstance(value, str) or not value for value in values):
        raise ValueError("Candidate结构化身份字段不能为空")
    payload = json.dumps(values, ensure_ascii=False, separators=(",", ":"))
    return "candidate:" + hashlib.sha256(payload.encode()).hexdigest()[:24]


@dataclass(frozen=True, slots=True)
class Candidate:
    id: str
    kind: CandidateKind
    rule_id: str
    analyzer: str
    analyzer_version: str
    snapshot_id: str
    entry_node_id: str
    operation_node_id: str
    root_cause_node_id: str
    path_node_ids: tuple[str, ...]
    locations: tuple[SourceLocation, ...]
    taint_kind: str
    flow_states: tuple[str, ...]
    controls: tuple[str, ...]
    assumptions: tuple[str, ...]
    unknowns: tuple[str, ...]
    evidence_origins: tuple[str, ...]
    status: CandidateStatus = CandidateStatus.NEEDS_REVIEW
    subject_node_id: str | None = None
    resource_node_id: str | None = None

    def __post_init__(self):
        expected = candidate_identity(self.rule_id, self.snapshot_id, self.entry_node_id,
                                      self.operation_node_id, self.root_cause_node_id,
                                      self.resource_node_id)
        if self.id != expected:
            raise ValueError("Candidate ID与结构化身份不一致")
        if not self.path_node_ids or len(self.path_node_ids) != len(self.locations):
            raise ValueError("Candidate路径必须逐节点绑定源码位置")
        if self.path_node_ids[0] != self.entry_node_id:
            raise ValueError("Candidate路径必须从入口/Source开始")
        if self.path_node_ids[-1] != self.operation_node_id:
            raise ValueError("Candidate路径必须以Effect/Operation结束")
        if not self.evidence_origins:
            raise ValueError("Candidate必须保留证据来源")
