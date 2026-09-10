"""[SECVAL-LEGACY-EXPERIMENTAL]
本模块属于安全分析内核（B腿），当前不参与生产审计，仅作研究路径保留。
已确认问题：9 种 EdgeKind 缺少生产者，导致多个分析器空转；
其 EFFECTS 规则表与 A 腿 _SINK_RULES 为同一批硬编码字面量。
详见 docs/leg-b-status.md。
"""
"""Business entity state-transition analysis over facts and verified invariants."""

import time
import tracemalloc
from dataclasses import dataclass

from secval.candidates import Candidate, CandidateKind, candidate_identity
from secval.facts import EdgeKind


@dataclass(frozen=True, slots=True)
class StateTransitionEvidence:
    invariant_id: str
    operation_node_id: str
    entity: str
    operation: str
    from_state: str | None
    to_state: str | None
    observed_conditions: tuple[str, ...]
    missing_conditions: tuple[str, ...]
    side_effects: tuple[str, ...]
    missing_side_effects: tuple[str, ...]
    repeatable: bool
    idempotency_control: str | None
    violations: tuple[str, ...]
    unknowns: tuple[str, ...]
    path_node_ids: tuple[str, ...]
    locations: tuple


@dataclass(frozen=True, slots=True)
class StateMachineAnalysisResult:
    candidates: tuple[Candidate, ...]
    counterevidence: tuple[StateTransitionEvidence, ...]
    assessments: tuple[StateTransitionEvidence, ...]
    metrics: dict


class StateMachineEngine:
    VERSION = "1.0"

    def __init__(self, facts, semantics):
        self.facts, self.semantics = facts, semantics

    def analyze(self, snapshot_id):
        started = time.perf_counter()
        owns_trace = not tracemalloc.is_tracing()
        if owns_trace:
            tracemalloc.start()
        try:
            nodes = {node.id: node for node in self.facts.nodes(snapshot_id)}
            incoming, outgoing, effects = {}, {}, {}
            for kind, target in ((EdgeKind.READS_STATE, incoming),
                                 (EdgeKind.WRITES_STATE, outgoing),
                                 (EdgeKind.CAUSES_EFFECT, effects)):
                for edge in self.facts.edges(snapshot_id, kind=kind):
                    target.setdefault(edge.source_id, []).append(nodes[edge.target_id])
            candidates, counterevidence, assessments = [], [], []
            for invariant in self.semantics.resolve_state_invariants():
                operations = [node for node in nodes.values()
                              if node.attributes.get("entity") == invariant.entity
                              and node.attributes.get("operation") == invariant.operation]
                for operation in operations:
                    reads, writes = incoming.get(operation.id, []), outgoing.get(operation.id, [])
                    from_state = operation.attributes.get("from_state")
                    to_state = operation.attributes.get("to_state")
                    if from_state is None and reads:
                        from_state = reads[-1].attributes.get("state")
                    if to_state is None and writes:
                        to_state = writes[-1].attributes.get("state")
                    observed = tuple(operation.attributes.get("preconditions", ()))
                    side_effects = tuple(dict.fromkeys(
                        (*operation.attributes.get("side_effects", ()),
                         *(row.attributes.get("effect") for row in effects.get(operation.id, [])
                           if row.attributes.get("effect")))))
                    missing_conditions = tuple(sorted(invariant.required_conditions - set(observed)))
                    missing_effects = tuple(sorted(invariant.required_side_effects - set(side_effects)))
                    violations = []
                    unknowns = []
                    if from_state is None or not operation.attributes.get("initial_state_known", True):
                        unknowns.append("initial state unknown")
                    elif from_state not in invariant.allowed_from:
                        violations.append("source state not allowed")
                    if to_state is None:
                        unknowns.append("target state unknown")
                    elif to_state not in invariant.allowed_to:
                        violations.append("target state not allowed")
                    if missing_conditions:
                        violations.append("required precondition missing")
                    if missing_effects:
                        violations.append("required side effect missing")
                    idempotency = operation.attributes.get("idempotency_control")
                    may_repeat = bool(operation.attributes.get("may_repeat"))
                    if may_repeat and not invariant.repeatable and not idempotency:
                        violations.append("non-repeatable operation can execute repeatedly")
                    path_nodes = tuple(dict.fromkeys(
                        (*(row.id for row in reads), operation.id,
                         *(row.id for row in writes), *(row.id for row in effects.get(operation.id, [])))))
                    evidence = StateTransitionEvidence(
                        invariant.id, operation.id, invariant.entity, invariant.operation,
                        from_state, to_state, observed, missing_conditions, side_effects,
                        missing_effects, invariant.repeatable, idempotency, tuple(violations),
                        tuple(unknowns), path_nodes,
                        tuple(nodes[item].location for item in path_nodes))
                    assessments.append(evidence)
                    if not violations and not unknowns:
                        counterevidence.append(evidence)
                        continue
                    entry = path_nodes[0]
                    rule = f"state-machine:{invariant.id}"
                    candidate_path = path_nodes
                    if candidate_path[-1] != operation.id:
                        candidate_path = (*candidate_path, operation.id)
                    candidates.append(Candidate(
                        candidate_identity(rule, snapshot_id, entry, operation.id, operation.id),
                        CandidateKind.STATE_MACHINE, rule, "state-machine", self.VERSION,
                        snapshot_id, entry, operation.id, operation.id, candidate_path,
                        tuple(nodes[item].location for item in candidate_path), "business_state", (),
                        (idempotency,) if idempotency else (),
                        (*violations, f"entity={invariant.entity}"), tuple(unknowns),
                        tuple(dict.fromkeys(nodes[item].origin for item in candidate_path))))
            _, peak = tracemalloc.get_traced_memory()
            metrics = {"snapshot_id": snapshot_id, "transitions": len(assessments),
                       "candidates": len(candidates), "valid": len(counterevidence),
                       "unknown_rate": (sum(bool(row.unknowns) for row in assessments) /
                                        len(assessments) if assessments else 0.0),
                       "elapsed_ms": round((time.perf_counter() - started) * 1000, 3),
                       "peak_memory_bytes": peak}
            return StateMachineAnalysisResult(tuple(candidates), tuple(counterevidence),
                                              tuple(assessments), metrics)
        finally:
            if owns_trace:
                tracemalloc.stop()
