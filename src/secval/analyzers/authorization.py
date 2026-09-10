"""Principal-resource authorization analysis built on facts and GuardEngine evidence."""

import time
import tracemalloc
from dataclasses import dataclass
from enum import StrEnum

from secval.analyzers.guard import GuardEngine
from secval.candidates import Candidate, CandidateKind, candidate_identity


class PrincipalTrust(StrEnum):
    SERVER_AUTHENTICATED = "server_authenticated"
    CLIENT_CONTROLLED = "client_controlled"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class AuthorizationEvidence:
    operation_node_id: str
    principal_node_id: str | None
    resource_node_id: str | None
    operation: str
    principal_trust: PrincipalTrust
    required_constraints: tuple[str, ...]
    proven_constraints: tuple[str, ...]
    guard_node_ids: tuple[str, ...]
    missing_constraints: tuple[str, ...]
    locations: tuple


@dataclass(frozen=True, slots=True)
class AuthorizationAnalysisResult:
    candidates: tuple[Candidate, ...]
    counterevidence: tuple[AuthorizationEvidence, ...]
    assessments: tuple[AuthorizationEvidence, ...]
    metrics: dict


class AuthorizationEngine:
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
            guard_result = GuardEngine(self.facts, self.semantics).analyze(snapshot_id)
            defended = {}
            for evidence in guard_result.counterevidence:
                defended.setdefault(evidence.effect_node_id, []).append(evidence)
            candidates, counterevidence, assessments = [], [], []
            for operation in nodes.values():
                required = tuple(operation.attributes.get("authorization_requirements", ()))
                if not required:
                    continue
                principal = nodes.get(operation.attributes.get("principal_node_id"))
                resource = nodes.get(operation.attributes.get("resource_node_id"))
                trust = self._trust(principal)
                guard_rows = defended.get(operation.id, [])
                guard_nodes = [nodes[row.guard_node_id] for row in guard_rows
                               if row.guard_node_id in nodes]
                proven = tuple(dict.fromkeys(
                    constraint for guard in guard_nodes
                    for constraint in guard.attributes.get("proves_constraints", ())))
                missing = tuple(item for item in required if item not in proven)
                unknowns = []
                if principal is None:
                    unknowns.append("principal fact missing")
                elif trust == PrincipalTrust.CLIENT_CONTROLLED:
                    missing = tuple(dict.fromkeys((*missing, "trusted_principal")))
                elif trust == PrincipalTrust.UNKNOWN:
                    unknowns.append("principal trust unknown")
                if resource is None:
                    unknowns.append("resource fact missing")
                locations = tuple(item.location for item in (principal, resource, operation)
                                  if item is not None)
                evidence = AuthorizationEvidence(
                    operation.id, principal.id if principal else None, resource.id if resource else None,
                    str(operation.attributes.get("operation", "unknown")), trust, required, proven,
                    tuple(guard.id for guard in guard_nodes), missing, locations)
                assessments.append(evidence)
                if not missing and not unknowns and trust == PrincipalTrust.SERVER_AUTHENTICATED:
                    counterevidence.append(evidence)
                    continue
                path = self._path_for_operation(operation.id, guard_result, nodes)
                rule = self._rule(missing or required)
                root = resource.id if resource else operation.id
                candidate_id = candidate_identity(rule, snapshot_id, path[0], operation.id, root)
                candidates.append(Candidate(
                    candidate_id, CandidateKind.AUTHORIZATION, rule, "authorization", self.VERSION,
                    snapshot_id, path[0], operation.id, root, path,
                    tuple(nodes[node_id].location for node_id in path), "resource_identity", (),
                    tuple(guard.id for guard in guard_nodes), (), tuple(unknowns),
                    tuple(dict.fromkeys(nodes[node_id].origin for node_id in path)),
                ))
            _, peak = tracemalloc.get_traced_memory()
            unknown = sum(bool(row.unknowns) for row in candidates)
            metrics = {"snapshot_id": snapshot_id, "operations": len(assessments),
                       "candidates": len(candidates), "defended": len(counterevidence),
                       "untrusted_principals": sum(
                           row.principal_trust == PrincipalTrust.CLIENT_CONTROLLED for row in assessments),
                       "unknown_rate": unknown / len(assessments) if assessments else 0.0,
                       "elapsed_ms": round((time.perf_counter() - started) * 1000, 3),
                       "peak_memory_bytes": peak}
            return AuthorizationAnalysisResult(tuple(candidates), tuple(counterevidence),
                                               tuple(assessments), metrics)
        finally:
            if owns_trace:
                tracemalloc.stop()

    @staticmethod
    def _trust(principal):
        if principal is None:
            return PrincipalTrust.UNKNOWN
        try:
            return PrincipalTrust(principal.attributes.get("trust", "unknown"))
        except ValueError:
            return PrincipalTrust.UNKNOWN

    @staticmethod
    def _path_for_operation(operation_id, guard_result, nodes):
        rows = [row for row in guard_result.assessments if row.effect_node_id == operation_id]
        for row in rows:
            paths = (*row.bypass_paths, *row.covered_paths)
            if paths:
                return tuple(paths[0])
        return (operation_id,)

    @staticmethod
    def _rule(requirements):
        values = set(requirements)
        if "trusted_principal" in values:
            return "authorization:untrusted-principal"
        if "ownership" in values:
            return "authorization:object-ownership"
        if "tenant" in values:
            return "authorization:tenant-boundary"
        if any(item.startswith("role:") for item in values):
            return "authorization:function-role"
        if any(item.startswith("permission:") for item in values):
            return "authorization:function-permission"
        return "authorization:missing-constraint"
