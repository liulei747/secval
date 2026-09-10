"""Effective configuration and dangerous resource-combination analysis."""

import time
import tracemalloc
from dataclasses import dataclass

from secval.candidates import Candidate, CandidateKind, candidate_identity
from secval.facts import NodeKind


@dataclass(frozen=True, slots=True)
class ConfigurationEvidence:
    policy_id: str
    effective_values: tuple[tuple[str, object], ...]
    raw_values: tuple[tuple[str, object], ...]
    override_chain: tuple[str, ...]
    consumer: str
    resource: str
    controls: tuple[str, ...]
    deployment_premises: tuple[str, ...]
    unknowns: tuple[str, ...]
    locations: tuple


@dataclass(frozen=True, slots=True)
class ConfigurationAnalysisResult:
    candidates: tuple[Candidate, ...]
    counterevidence: tuple[ConfigurationEvidence, ...]
    assessments: tuple[ConfigurationEvidence, ...]
    metrics: dict


class ConfigurationEngine:
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
            configs = [node for node in nodes.values() if node.kind == NodeKind.CONFIG]
            by_key = {}
            for node in configs:
                by_key.setdefault(node.attributes.get("config_key"), []).append(node)
            effective = {key: max(rows, key=lambda row: (row.attributes.get("precedence", 0), row.id))
                         for key, rows in by_key.items()}
            candidates, counterevidence, assessments = [], [], []
            for policy in self.semantics.resolve_configuration_policies():
                keys = (policy.activation_key, policy.exposure_key, policy.control_key)
                selected = [effective.get(key) for key in keys]
                unknowns = []
                for key, node in zip(keys, selected):
                    if node is None:
                        unknowns.append(f"effective value missing: {key}")
                    elif node.attributes.get("unresolved"):
                        unknowns.append(f"effective value unresolved: {key}")
                values = tuple((key, node.attributes.get("raw_value") if node else None)
                               for key, node in zip(keys, selected))
                activation, exposure, control = (value for _, value in values)
                active = activation in policy.activation_values
                exposed = exposure in policy.exposure_values
                protected = control in policy.safe_control_values
                involved = [node for node in selected if node is not None]
                chain = tuple(node.id for key in keys for node in sorted(
                    by_key.get(key, ()), key=lambda row: (row.attributes.get("precedence", 0), row.id)))
                evidence = ConfigurationEvidence(
                    policy.id, values,
                    tuple((node.attributes["config_key"], node.attributes.get("raw_value"))
                          for key in keys for node in by_key.get(key, ())), chain,
                    policy.consumer, policy.resource,
                    (policy.control_key,) if protected else (),
                    tuple(f"{node.attributes.get('layer')}:{node.location.path}" for node in involved
                          if node.attributes.get("layer") == "deployment"),
                    tuple(unknowns), tuple(node.location for node in involved))
                assessments.append(evidence)
                dangerous = active and exposed and not protected
                if not dangerous and not unknowns:
                    counterevidence.append(evidence)
                    continue
                if not involved:
                    continue
                operation = selected[1] or involved[-1]
                entry = selected[0] or involved[0]
                root = selected[2] or operation
                rule = f"configuration:{policy.id}"
                path = tuple(dict.fromkeys(node.id for node in involved))
                if path[0] != entry.id:
                    path = (entry.id, *tuple(item for item in path if item != entry.id))
                if path[-1] != operation.id:
                    path = (*tuple(item for item in path if item != operation.id), operation.id)
                candidates.append(Candidate(
                    candidate_identity(rule, snapshot_id, entry.id, operation.id, root.id),
                    CandidateKind.CONFIGURATION, rule, "configuration", self.VERSION,
                    snapshot_id, entry.id, operation.id, root.id, path,
                    tuple(nodes[item].location for item in path), "configuration", (),
                    evidence.controls, (f"consumer={policy.consumer}", f"resource={policy.resource}"),
                    tuple(unknowns), tuple(dict.fromkeys(nodes[item].origin for item in path))))
            _, peak = tracemalloc.get_traced_memory()
            metrics = {"snapshot_id": snapshot_id, "policies": len(assessments),
                       "config_nodes": len(configs), "candidates": len(candidates),
                       "defended": len(counterevidence),
                       "unknown_rate": (sum(bool(row.unknowns) for row in assessments) /
                                        len(assessments) if assessments else 0.0),
                       "elapsed_ms": round((time.perf_counter() - started) * 1000, 3),
                       "peak_memory_bytes": peak}
            return ConfigurationAnalysisResult(tuple(candidates), tuple(counterevidence),
                                               tuple(assessments), metrics)
        finally:
            if owns_trace:
                tracemalloc.stop()
