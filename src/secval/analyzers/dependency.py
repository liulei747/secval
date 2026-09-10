"""Dependency presence, vulnerable API, entry reachability, and activation analysis."""

import time
import tracemalloc
from collections import deque
from dataclasses import dataclass
from enum import IntEnum

from secval.candidates import Candidate, CandidateKind, candidate_identity
from secval.facts import EdgeKind, NodeKind


class ReachabilityLevel(IntEnum):
    DEPENDENCY_PRESENT = 1
    VULNERABLE_API_CALLED = 2
    EXTERNAL_ENTRY_REACHABLE = 3
    RUNTIME_ACTIVATED = 4


@dataclass(frozen=True, slots=True)
class DependencyEvidence:
    advisory_id: str
    dependency_node_id: str
    package: str
    version: str
    affected: bool
    level: ReachabilityLevel | None
    call_node_ids: tuple[str, ...]
    entry_path: tuple[str, ...]
    activation_value: object
    unknowns: tuple[str, ...]
    locations: tuple


@dataclass(frozen=True, slots=True)
class DependencyAnalysisResult:
    candidates: tuple[Candidate, ...]
    counterevidence: tuple[DependencyEvidence, ...]
    assessments: tuple[DependencyEvidence, ...]
    metrics: dict


class DependencyReachabilityEngine:
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
            successors = {}
            for kind in (EdgeKind.CALLS, EdgeKind.FLOWS_TO):
                for edge in self.facts.edges(snapshot_id, kind=kind):
                    successors.setdefault(edge.source_id, []).append(edge.target_id)
            entries = [node.id for node in nodes.values() if node.attributes.get("external_entry")]
            configs = {}
            for node in nodes.values():
                if node.kind == NodeKind.CONFIG:
                    key = node.attributes.get("config_key")
                    current = configs.get(key)
                    if current is None or node.attributes.get("precedence", 0) > current.attributes.get("precedence", 0):
                        configs[key] = node
            candidates, counterevidence, assessments = [], [], []
            dependencies = [node for node in nodes.values() if node.kind == NodeKind.DEPENDENCY]
            for advisory in self.semantics.resolve_dependency_advisories():
                for dependency in dependencies:
                    if dependency.attributes.get("package") != advisory.package:
                        continue
                    version = str(dependency.attributes.get("version", ""))
                    unknowns = []
                    try:
                        affected = advisory.affects(version)
                    except ValueError:
                        affected = True
                        unknowns.append("dependency version unresolved")
                    calls = [node for node in nodes.values()
                             if node.attributes.get("signature") in advisory.vulnerable_signatures]
                    path = self._first_path(entries, {node.id for node in calls}, successors)
                    activation = None
                    activated = advisory.activation_key is None
                    if advisory.activation_key:
                        config = configs.get(advisory.activation_key)
                        if config is None or config.attributes.get("unresolved"):
                            unknowns.append("runtime activation unknown")
                        else:
                            activation = config.attributes.get("raw_value")
                            activated = activation in advisory.activation_values
                    level = ReachabilityLevel.DEPENDENCY_PRESENT if affected else None
                    if affected and calls:
                        level = ReachabilityLevel.VULNERABLE_API_CALLED
                    if affected and path:
                        level = ReachabilityLevel.EXTERNAL_ENTRY_REACHABLE
                    if affected and path and activated:
                        level = ReachabilityLevel.RUNTIME_ACTIVATED
                    if affected and not calls:
                        unknowns.append("vulnerable API not observed")
                    evidence = DependencyEvidence(
                        advisory.id, dependency.id, advisory.package, version, affected, level,
                        tuple(node.id for node in calls), tuple(path), activation, tuple(unknowns),
                        tuple(node.location for node in ([nodes[item] for item in path] or [dependency])))
                    assessments.append(evidence)
                    if not affected or (calls and not path) or (path and not activated and not unknowns):
                        counterevidence.append(evidence)
                        continue
                    operation = nodes[path[-1]] if path else (calls[0] if calls else dependency)
                    entry = nodes[path[0]] if path else dependency
                    candidate_path = tuple(path) if path else (entry.id,) if entry == operation else (entry.id, operation.id)
                    rule = f"dependency:{advisory.id}"
                    candidates.append(Candidate(
                        candidate_identity(rule, snapshot_id, entry.id, operation.id, dependency.id),
                        CandidateKind.DEPENDENCY, rule, "dependency-reachability", self.VERSION,
                        snapshot_id, entry.id, operation.id, dependency.id, candidate_path,
                        tuple(nodes[item].location for item in candidate_path), "dependency", (), (),
                        (f"level={level.name if level else 'unaffected'}",), tuple(unknowns),
                        tuple(dict.fromkeys(nodes[item].origin for item in candidate_path))))
            _, peak = tracemalloc.get_traced_memory()
            metrics = {"snapshot_id": snapshot_id, "dependencies": len(dependencies),
                       "assessments": len(assessments), "candidates": len(candidates),
                       "counterevidence": len(counterevidence),
                       "unknown_rate": (sum(bool(row.unknowns) for row in assessments) /
                                        len(assessments) if assessments else 0.0),
                       "elapsed_ms": round((time.perf_counter() - started) * 1000, 3),
                       "peak_memory_bytes": peak}
            return DependencyAnalysisResult(tuple(candidates), tuple(counterevidence),
                                            tuple(assessments), metrics)
        finally:
            if owns_trace:
                tracemalloc.stop()

    @staticmethod
    def _first_path(entries, targets, successors):
        queue = deque((entry, (entry,)) for entry in entries)
        visited = set(entries)
        while queue:
            current, path = queue.popleft()
            if current in targets:
                return path
            for child in successors.get(current, ()):
                if child not in visited:
                    visited.add(child)
                    queue.append((child, (*path, child)))
        return ()
