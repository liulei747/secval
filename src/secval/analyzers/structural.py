"""[SECVAL-LEGACY-EXPERIMENTAL]
本模块属于安全分析内核（B腿），当前不参与生产审计，仅作研究路径保留。
已确认问题：9 种 EdgeKind 缺少生产者，导致多个分析器空转；
其 EFFECTS 规则表与 A 腿 _SINK_RULES 为同一批硬编码字面量。
详见 docs/leg-b-status.md。
"""
"""Signature, typed constant propagation, and security-use context analysis."""

import time
import tracemalloc
from dataclasses import dataclass

from secval.candidates import Candidate, CandidateKind, candidate_identity
from secval.facts import EdgeKind


@dataclass(frozen=True, slots=True)
class StructuralEvidence:
    policy_id: str
    operation_node_id: str
    signature: str
    type_name: str | None
    constant_value: object
    usage_context: str | None
    value_node_ids: tuple[str, ...]
    sensitive_use: bool
    dangerous_value: bool
    unknowns: tuple[str, ...]
    locations: tuple


@dataclass(frozen=True, slots=True)
class StructuralAnalysisResult:
    candidates: tuple[Candidate, ...]
    counterevidence: tuple[StructuralEvidence, ...]
    assessments: tuple[StructuralEvidence, ...]
    metrics: dict


class StructuralEngine:
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
            values_for = {}
            for edge in self.facts.edges(snapshot_id, kind=EdgeKind.DEFINES_USES):
                values_for.setdefault(edge.target_id, []).append(edge.source_id)
            candidates, counterevidence, assessments = [], [], []
            for policy in self.semantics.resolve_structural_policies():
                for operation in nodes.values():
                    signature = operation.attributes.get("signature")
                    if signature not in policy.signatures:
                        continue
                    value_nodes = self._value_nodes(operation.id, values_for, nodes)
                    raw = operation.attributes.get("constant_value")
                    if raw is None and value_nodes:
                        raw = value_nodes[-1].attributes.get("constant_value")
                    context = operation.attributes.get("usage_context")
                    unknowns = []
                    if raw is None:
                        unknowns.append("constant propagation incomplete")
                    if context is None:
                        unknowns.append("security usage context missing")
                    dangerous = raw in policy.dangerous_values
                    sensitive = context in policy.sensitive_contexts
                    path_nodes = (*value_nodes, operation)
                    evidence = StructuralEvidence(
                        policy.id, operation.id, signature, operation.attributes.get("type_name"),
                        raw, context, tuple(node.id for node in value_nodes), sensitive, dangerous,
                        tuple(unknowns), tuple(node.location for node in path_nodes))
                    assessments.append(evidence)
                    if not unknowns and not (dangerous and sensitive):
                        counterevidence.append(evidence)
                        continue
                    entry = value_nodes[0] if value_nodes else operation
                    rule = f"structural:{policy.id}"
                    path = tuple(node.id for node in path_nodes)
                    candidates.append(Candidate(
                        candidate_identity(rule, snapshot_id, entry.id, operation.id, operation.id),
                        CandidateKind.STRUCTURAL, rule, "structural", self.VERSION, snapshot_id,
                        entry.id, operation.id, operation.id, path,
                        tuple(node.location for node in path_nodes), "constant", (), (),
                        (f"signature={signature}", f"context={context}"), tuple(unknowns),
                        tuple(dict.fromkeys(node.origin for node in path_nodes))))
            _, peak = tracemalloc.get_traced_memory()
            metrics = {"snapshot_id": snapshot_id, "operations": len(assessments),
                       "candidates": len(candidates), "counterevidence": len(counterevidence),
                       "unknown_rate": (sum(bool(row.unknowns) for row in assessments) /
                                        len(assessments) if assessments else 0.0),
                       "elapsed_ms": round((time.perf_counter() - started) * 1000, 3),
                       "peak_memory_bytes": peak}
            return StructuralAnalysisResult(tuple(candidates), tuple(counterevidence),
                                            tuple(assessments), metrics)
        finally:
            if owns_trace:
                tracemalloc.stop()

    @staticmethod
    def _value_nodes(operation_id, predecessors, nodes):
        result, visited, stack = [], {operation_id}, list(predecessors.get(operation_id, ()))
        while stack:
            node_id = stack.pop()
            if node_id in visited:
                continue
            visited.add(node_id)
            node = nodes.get(node_id)
            if node is not None:
                result.insert(0, node)
            stack.extend(predecessors.get(node_id, ()))
        return result
