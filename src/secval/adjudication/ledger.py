"""[SECVAL-LEGACY-EXPERIMENTAL]
本模块属于安全分析内核（B腿），当前不参与生产审计，仅作研究路径保留。
已确认问题：9 种 EdgeKind 缺少生产者，导致多个分析器空转；
其 EFFECTS 规则表与 A 腿 _SINK_RULES 为同一批硬编码字面量。
详见 docs/leg-b-status.md。
"""
"""Append-only candidate ledger with evidence-gated six-state adjudication."""

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from enum import StrEnum


class Verdict(StrEnum):
    CONFIRMED = "CONFIRMED"
    REJECTED = "REJECTED"
    UNREACHABLE = "UNREACHABLE"
    DEFENDED = "DEFENDED"
    DUPLICATE = "DUPLICATE"
    NEEDS_REVIEW = "NEEDS_REVIEW"


@dataclass(frozen=True, slots=True)
class LedgerEvent:
    sequence: int
    candidate_id: str
    snapshot_id: str
    verdict: Verdict
    reason: str
    evidence_ids: tuple[str, ...]
    tool_versions: tuple[str, ...]
    closure_hash: str
    timestamp: str
    previous_hash: str
    event_hash: str
    duplicate_of: str | None = None


class CandidateLedger:
    def __init__(self):
        self._candidates, self._events = {}, []

    def ingest(self, candidate, closure_hash):
        existing = self._candidates.get(candidate.id)
        if existing is None:
            self._candidates[candidate.id] = [candidate]
            self.append(candidate.id, Verdict.NEEDS_REVIEW, "candidate ingested", (),
                        (f"{candidate.analyzer}@{candidate.analyzer_version}",), closure_hash)
        elif candidate not in existing:
            existing.append(candidate)
        return candidate.id

    def append(self, candidate_id, verdict, reason, evidence_ids, tool_versions, closure_hash,
               *, duplicate_of=None, entry_absence_proven=False, all_paths_covered=False):
        if candidate_id not in self._candidates:
            raise KeyError("候选必须先写入Ledger")
        verdict = Verdict(verdict)
        candidate = self._candidates[candidate_id][0]
        if not reason or not closure_hash or not tool_versions:
            raise ValueError("裁决必须记录理由、闭包和工具版本")
        if verdict == Verdict.CONFIRMED and (candidate.unknowns or not evidence_ids):
            raise ValueError("存在未知项或缺少证据时不能确认")
        if verdict == Verdict.REJECTED and not evidence_ids:
            raise ValueError("拒绝候选必须有反证")
        if verdict == Verdict.UNREACHABLE and not entry_absence_proven:
            raise ValueError("未找到入口不能判定UNREACHABLE")
        if verdict == Verdict.DEFENDED and (not evidence_ids or not all_paths_covered):
            raise ValueError("DEFENDED必须证明控制覆盖全部路径")
        if verdict == Verdict.DUPLICATE and (
                not duplicate_of or duplicate_of == candidate_id or duplicate_of not in self._candidates):
            raise ValueError("DUPLICATE必须指向另一已存在候选")
        timestamp = datetime.now(UTC).isoformat()
        previous = self._events[-1].event_hash if self._events else "GENESIS"
        payload = (len(self._events) + 1, candidate_id, candidate.snapshot_id, verdict, reason,
                   tuple(evidence_ids), tuple(tool_versions), closure_hash, timestamp, previous,
                   duplicate_of)
        digest = hashlib.sha256(json.dumps(payload, ensure_ascii=False,
                                           separators=(",", ":")).encode()).hexdigest()
        event = LedgerEvent(len(self._events) + 1, candidate_id, candidate.snapshot_id, verdict,
                            reason, tuple(evidence_ids), tuple(tool_versions), closure_hash,
                            timestamp, previous, digest, duplicate_of)
        self._events.append(event)
        return event

    def invalidate_changed_closure(self, candidate_id, closure_hash, tool_versions):
        current = self.current(candidate_id)
        if current.closure_hash == closure_hash:
            return None
        return self.append(candidate_id, Verdict.NEEDS_REVIEW, "dependency closure changed", (),
                           tool_versions, closure_hash)

    def current(self, candidate_id):
        return next(event for event in reversed(self._events)
                    if event.candidate_id == candidate_id)

    def candidates(self):
        return tuple(rows[0] for _, rows in sorted(self._candidates.items()))

    def variants(self, candidate_id):
        return tuple(self._candidates[candidate_id])

    def events(self):
        return tuple(self._events)

    def verify_chain(self):
        previous = "GENESIS"
        for event in self._events:
            values = asdict(event)
            digest = values.pop("event_hash")
            payload = (values["sequence"], values["candidate_id"], values["snapshot_id"],
                       Verdict(values["verdict"]), values["reason"],
                       tuple(values["evidence_ids"]), tuple(values["tool_versions"]),
                       values["closure_hash"], values["timestamp"], values["previous_hash"],
                       values["duplicate_of"])
            expected = hashlib.sha256(json.dumps(payload, ensure_ascii=False,
                                                 separators=(",", ":")).encode()).hexdigest()
            if event.previous_hash != previous or digest != expected:
                return False
            previous = digest
        return True

    def snapshot(self):
        return {
            "candidate_variants": {
                candidate_id: [asdict(candidate) for candidate in variants]
                for candidate_id, variants in self._candidates.items()
            },
            "events": [asdict(event) for event in self._events],
        }

    @classmethod
    def restore(cls, snapshot):
        from secval.candidates import Candidate, CandidateKind, CandidateStatus
        from secval.facts import SourceLocation

        ledger = cls()
        for candidate_id, variants in snapshot.get("candidate_variants", {}).items():
            restored = []
            for values in variants:
                values = dict(values)
                values["kind"] = CandidateKind(values["kind"])
                values["status"] = CandidateStatus(values.get("status", "NEEDS_REVIEW"))
                values["locations"] = tuple(SourceLocation(**row) for row in values["locations"])
                for key in ("path_node_ids", "flow_states", "controls", "assumptions",
                            "unknowns", "evidence_origins"):
                    values[key] = tuple(values[key])
                restored.append(Candidate(**values))
            ledger._candidates[candidate_id] = restored
        ledger._events = [LedgerEvent(**{
            **row,
            "verdict": Verdict(row["verdict"]),
            "evidence_ids": tuple(row["evidence_ids"]),
            "tool_versions": tuple(row["tool_versions"]),
        }) for row in snapshot.get("events", [])]
        if not ledger.verify_chain():
            raise ValueError("持久化CandidateLedger哈希链无效")
        return ledger
