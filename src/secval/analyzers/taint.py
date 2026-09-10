"""[SECVAL-LEGACY-EXPERIMENTAL]
本模块属于安全分析内核（B腿），当前不参与生产审计，仅作研究路径保留。
已确认问题：9 种 EdgeKind 缺少生产者，导致多个分析器空转；
其 EFFECTS 规则表与 A 腿 _SINK_RULES 为同一批硬编码字面量。
详见 docs/leg-b-status.md。
"""

"""Snapshot-scoped, kind-aware bidirectional taint/effect analysis."""

import time
import tracemalloc
from collections import deque
from dataclasses import dataclass

from secval.candidates import Candidate, CandidateKind, candidate_identity
from secval.facts import EdgeKind
from secval.semantics import ModelKind

FLOW_EDGES = frozenset({
    EdgeKind.ARGUMENT_TO_PARAMETER,
    EdgeKind.RETURNS_TO,
    EdgeKind.DEFINES_USES,
})


@dataclass(frozen=True, slots=True)
class TaintAnalysisResult:
    candidates: tuple[Candidate, ...]
    counterevidence: tuple["FlowBlock", ...]
    metrics: dict


@dataclass(frozen=True, slots=True)
class FlowBlock:
    source_node_id: str
    control_node_id: str
    taint_kind: str
    reason: str
    locations: tuple


class TaintEngine:
    VERSION = "1.0"

    def __init__(self, facts, semantics):
        self.facts = facts
        self.semantics = semantics

    def analyze(self, snapshot_id, *, language, framework, version, project_id=None):
        started = time.perf_counter()
        owns_trace = not tracemalloc.is_tracing()
        if owns_trace:
            tracemalloc.start()
        try:
            nodes = {node.id: node for node in self.facts.nodes(snapshot_id)}
            models = self.semantics.resolve_models(
                language, framework, version, project_id=project_id)
            source_models = [row for row in models if row.kind == ModelKind.SOURCE]
            effect_models = [row for row in models if row.kind == ModelKind.EFFECT]
            sanitizer_models = [row for row in models if row.kind == ModelKind.SANITIZER]
            signatures = {node.id: node.attributes.get("signature") for node in nodes.values()}
            sources = [(node, model) for node in nodes.values() for model in source_models
                       if signatures[node.id] == model.signature]
            effects = [(node, model) for node in nodes.values() for model in effect_models
                       if signatures[node.id] == model.signature]
            sanitizers = {node.id: model for node in nodes.values() for model in sanitizer_models
                          if signatures[node.id] == model.signature}
            edges = [edge for edge in self.facts.edges(snapshot_id) if edge.kind in FLOW_EDGES]
            outgoing, incoming = {}, {}
            for edge in edges:
                outgoing.setdefault(edge.source_id, []).append(edge)
                incoming.setdefault(edge.target_id, []).append(edge)
            candidates = []
            counterevidence = []
            for source, source_model in sources:
                kinds = source_model.taint_kinds or frozenset({"untyped"})
                for taint_kind in sorted(kinds):
                    forward, parent, blocks = self._forward(
                        source.id, taint_kind, outgoing, nodes, sanitizers)
                    counterevidence.extend(blocks)
                    for effect, effect_model in effects:
                        if effect_model.taint_kinds and taint_kind not in effect_model.taint_kinds:
                            continue
                        reverse = self._reverse(effect.id, taint_kind, incoming)
                        if effect.id not in forward or source.id not in reverse:
                            continue
                        path = self._path(source.id, effect.id, parent)
                        candidates.append(self._candidate(
                            snapshot_id, CandidateKind.TAINT_FLOW, effect_model.id, path, nodes,
                            taint_kind, (), (), ("joern-cpg", "semantic-registry")))
                    candidates.extend(self._unknown_effects(
                        snapshot_id, source.id, taint_kind, forward, parent, nodes))
            candidates = tuple({candidate.id: candidate for candidate in candidates}.values())
            _, peak = tracemalloc.get_traced_memory()
            unknown = sum(row.kind == CandidateKind.UNKNOWN_EFFECT for row in candidates)
            metrics = {"snapshot_id": snapshot_id, "sources": len(sources), "effects": len(effects),
                       "candidates": len(candidates), "unknown_effects": unknown,
                       "blocked_flows": len(counterevidence),
                       "unknown_rate": unknown / len(candidates) if candidates else 0.0,
                       "elapsed_ms": round((time.perf_counter() - started) * 1000, 3),
                       "peak_memory_bytes": peak}
            return TaintAnalysisResult(candidates, tuple(counterevidence), metrics)
        finally:
            if owns_trace:
                tracemalloc.stop()

    @staticmethod
    def _forward(start, taint_kind, outgoing, nodes, sanitizers):
        reached, parent, blocks = {start}, {}, []
        queue = deque([start])
        while queue:
            current = queue.popleft()
            for edge in outgoing.get(current, ()):
                allowed = set(edge.attributes.get("taint_kinds", ()))
                if allowed and taint_kind not in allowed:
                    continue
                target = edge.target_id
                sanitizer = sanitizers.get(target)
                if sanitizer and (not sanitizer.taint_kinds or taint_kind in sanitizer.taint_kinds):
                    blocks.append(FlowBlock(start, target, taint_kind,
                                            f"verified sanitizer: {sanitizer.id}",
                                            (nodes[start].location, nodes[target].location)))
                    continue
                cleared = set(nodes[target].attributes.get("clears_taint_kinds", ()))
                if taint_kind in cleared:
                    blocks.append(FlowBlock(start, target, taint_kind,
                                            "fact node clears this taint kind",
                                            (nodes[start].location, nodes[target].location)))
                    continue
                if target in reached:
                    continue
                reached.add(target)
                parent[target] = current
                queue.append(target)
        return reached, parent, blocks

    @staticmethod
    def _reverse(start, taint_kind, incoming):
        reached, queue = {start}, deque([start])
        while queue:
            current = queue.popleft()
            for edge in incoming.get(current, ()):
                allowed = set(edge.attributes.get("taint_kinds", ()))
                if allowed and taint_kind not in allowed:
                    continue
                if edge.source_id not in reached:
                    reached.add(edge.source_id)
                    queue.append(edge.source_id)
        return reached

    @staticmethod
    def _path(source, target, parent):
        path = [target]
        while path[-1] != source:
            path.append(parent[path[-1]])
        return tuple(reversed(path))

    def _unknown_effects(self, snapshot_id, source_id, taint_kind, reached, parent, nodes):
        candidates = []
        for gap in self.facts.gaps(snapshot_id):
            if gap.category not in {"missing_dependency", "dynamic_dispatch", "native_call"}:
                continue
            endpoints = [node_id for node_id in reached
                         if nodes[node_id].location.path == gap.location.path
                         and nodes[node_id].location.start_line <= gap.location.start_line]
            if not endpoints:
                continue
            endpoint = max(endpoints, key=lambda node_id: nodes[node_id].location.start_line)
            path = self._path(source_id, endpoint, parent) if endpoint != source_id else (source_id,)
            candidates.append(self._candidate(
                snapshot_id, CandidateKind.UNKNOWN_EFFECT, "unknown-effect", path, nodes,
                taint_kind, (), (gap.reason,), (gap.origin,), root_cause=gap.id))
        return candidates

    def _candidate(self, snapshot_id, kind, rule_id, path, nodes, taint_kind, controls,
                   unknowns, origins, *, root_cause=None):
        operation = path[-1]
        states = []
        for node_id in path:
            states.extend(nodes[node_id].attributes.get("flow_states", ()))
        root_cause = root_cause or path[0]
        candidate_id = candidate_identity(rule_id, snapshot_id, path[0], operation, root_cause)
        return Candidate(candidate_id, kind, rule_id, "taint", self.VERSION, snapshot_id,
                         path[0], operation, root_cause, path,
                         tuple(nodes[node_id].location for node_id in path), taint_kind,
                         tuple(dict.fromkeys(states)), tuple(controls), (), tuple(unknowns),
                         tuple(dict.fromkeys(origins)))
