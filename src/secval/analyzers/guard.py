"""[SECVAL-LEGACY-EXPERIMENTAL]
本模块属于安全分析内核（B腿），当前不参与生产审计，仅作研究路径保留。
已确认问题：9 种 EdgeKind 缺少生产者，导致多个分析器空转；
其 EFFECTS 规则表与 A 腿 _SINK_RULES 为同一批硬编码字面量。
详见 docs/leg-b-status.md。
"""
"""CFG dominance, same-value, failure-termination, and bypass analysis."""

import time
import tracemalloc
from collections import deque
from dataclasses import dataclass

from secval.candidates import Candidate, CandidateKind, candidate_identity
from secval.facts import EdgeKind
from secval.semantics import FailureBehavior


@dataclass(frozen=True, slots=True)
class GuardEvidence:
    effect_node_id: str
    guard_node_id: str | None
    dominates: bool
    same_value: bool
    failure_terminates: bool
    covered_paths: tuple[tuple[str, ...], ...]
    bypass_paths: tuple[tuple[str, ...], ...]
    locations: tuple


@dataclass(frozen=True, slots=True)
class GuardAnalysisResult:
    candidates: tuple[Candidate, ...]
    counterevidence: tuple[GuardEvidence, ...]
    assessments: tuple[GuardEvidence, ...]
    metrics: dict


class GuardEngine:
    VERSION = "1.0"

    def __init__(self, facts, semantics):
        self.facts = facts
        self.semantics = semantics

    def analyze(self, snapshot_id):
        started = time.perf_counter()
        owns_trace = not tracemalloc.is_tracing()
        if owns_trace:
            tracemalloc.start()
        try:
            nodes = {node.id: node for node in self.facts.nodes(snapshot_id)}
            successors, predecessors = {}, {}
            for edge in self.facts.edges(snapshot_id, kind=EdgeKind.FLOWS_TO):
                successors.setdefault(edge.source_id, []).append(edge.target_id)
                predecessors.setdefault(edge.target_id, []).append(edge.source_id)
            entries = [node.id for node in nodes.values() if node.attributes.get("entry")]
            if not entries:
                entries = [node_id for node_id in nodes if node_id not in predecessors]
            reachable = self._reachable(entries, successors)
            dominators = self._dominators(entries, reachable, predecessors)
            controls = {row.signature: row for row in self.semantics.resolve_controls()}
            guards = [(node, controls[node.attributes.get("signature")]) for node in nodes.values()
                      if node.attributes.get("signature") in controls]
            candidates, counterevidence, assessments = [], [], []
            for effect in nodes.values():
                required = effect.attributes.get("requires_guard")
                if not required:
                    continue
                checked_value = effect.attributes.get("guarded_value_id")
                known_contracts = [contract for contract in controls.values()
                                   if required in contract.applicable_taint_kinds]
                applicable = [(guard, contract) for guard, contract in guards
                              if required in contract.applicable_taint_kinds]
                evidence = [self._assess(effect, checked_value, guard, contract, entries,
                                         successors, dominators, nodes)
                            for guard, contract in applicable]
                defended = next((row for row in evidence if row.dominates and row.same_value
                                 and row.failure_terminates and not row.bypass_paths), None)
                if defended:
                    counterevidence.append(defended)
                    assessments.extend(evidence)
                    continue
                excluded = {row.guard_node_id for row in evidence if row.guard_node_id}
                bypass = self._first_path(entries, effect.id, successors, excluded=excluded)
                if not bypass:
                    bypass = self._first_path(entries, effect.id, successors)
                if not bypass:
                    continue
                rule_id = f"missing-guard:{required}"
                candidate_id = candidate_identity(rule_id, snapshot_id, bypass[0], effect.id, effect.id)
                unknowns = ("guard contract not found",) if not known_contracts else ()
                candidates.append(Candidate(
                    candidate_id, CandidateKind.MISSING_GUARD, rule_id, "guard", self.VERSION,
                    snapshot_id, bypass[0], effect.id, effect.id, tuple(bypass),
                    tuple(nodes[item].location for item in bypass), "control", (),
                    tuple(row.guard_node_id for row in evidence if row.guard_node_id), (), unknowns,
                    tuple(dict.fromkeys(nodes[item].origin for item in bypass)),
                ))
                assessments.extend(evidence or [GuardEvidence(
                    effect.id, None, False, False, False, (), (tuple(bypass),),
                    tuple(nodes[item].location for item in bypass))])
            _, peak = tracemalloc.get_traced_memory()
            metrics = {"snapshot_id": snapshot_id, "effects": len(candidates) + len(counterevidence),
                       "candidates": len(candidates), "defended": len(counterevidence),
                       "bypass_paths": sum(len(row.bypass_paths) for row in assessments),
                       "elapsed_ms": round((time.perf_counter() - started) * 1000, 3),
                       "peak_memory_bytes": peak}
            return GuardAnalysisResult(tuple(candidates), tuple(counterevidence),
                                       tuple(assessments), metrics)
        finally:
            if owns_trace:
                tracemalloc.stop()

    @staticmethod
    def _reachable(entries, successors):
        reached, queue = set(entries), deque(entries)
        while queue:
            for target in successors.get(queue.popleft(), ()):
                if target not in reached:
                    reached.add(target)
                    queue.append(target)
        return reached

    @staticmethod
    def _dominators(entries, reachable, predecessors):
        dominators = {node: ({node} if node in entries else set(reachable)) for node in reachable}
        changed = True
        while changed:
            changed = False
            for node in reachable - set(entries):
                parents = [parent for parent in predecessors.get(node, ()) if parent in reachable]
                updated = {node} | (set.intersection(*(dominators[parent] for parent in parents))
                                    if parents else set())
                if updated != dominators[node]:
                    dominators[node] = updated
                    changed = True
        return dominators

    def _assess(self, effect, checked_value, guard, contract, entries, successors, dominators, nodes):
        dominates = guard.id in dominators.get(effect.id, set())
        same_value = checked_value in set(guard.attributes.get("checked_value_ids", ()))
        failure_terminates = contract.failure_behavior in {
            FailureBehavior.TERMINATES, FailureBehavior.THROWS} or bool(
                guard.attributes.get("failure_terminates"))
        bypass = self._first_path(entries, effect.id, successors, excluded={guard.id})
        covered = self._first_path(entries, effect.id, successors)
        return GuardEvidence(effect.id, guard.id, dominates, same_value, failure_terminates,
                             (tuple(covered),) if covered and not bypass else (),
                             (tuple(bypass),) if bypass else (),
                             (guard.location, effect.location))

    @staticmethod
    def _first_path(entries, target, successors, excluded=frozenset()):
        queue = deque((entry, (entry,)) for entry in entries if entry not in excluded)
        visited = {entry for entry in entries if entry not in excluded}
        while queue:
            current, path = queue.popleft()
            if current == target:
                return path
            for child in successors.get(current, ()):
                if child not in excluded and child not in visited:
                    visited.add(child)
                    queue.append((child, (*path, child)))
        return ()
