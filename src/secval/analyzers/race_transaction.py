"""READ-CHECK-WRITE and transaction-control analysis."""

import time
import tracemalloc
from dataclasses import dataclass

from secval.candidates import Candidate, CandidateKind, candidate_identity
from secval.facts import EdgeKind


@dataclass(frozen=True, slots=True)
class RaceTransactionEvidence:
    invariant_id: str
    operation_node_id: str
    resource_node_id: str | None
    read_node_ids: tuple[str, ...]
    check_node_ids: tuple[str, ...]
    write_node_ids: tuple[str, ...]
    same_resource: bool
    transaction_node_ids: tuple[str, ...]
    isolation_level: str | None
    controls: tuple[str, ...]
    accepted_controls: tuple[str, ...]
    violations: tuple[str, ...]
    unknowns: tuple[str, ...]
    locations: tuple


@dataclass(frozen=True, slots=True)
class RaceTransactionAnalysisResult:
    candidates: tuple[Candidate, ...]
    counterevidence: tuple[RaceTransactionEvidence, ...]
    assessments: tuple[RaceTransactionEvidence, ...]
    metrics: dict


class RaceTransactionEngine:
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
            links = {kind: {} for kind in (EdgeKind.READS_RESOURCE, EdgeKind.CHECKS_RESOURCE,
                                           EdgeKind.WRITES_RESOURCE, EdgeKind.IN_TRANSACTION)}
            for kind, table in links.items():
                for edge in self.facts.edges(snapshot_id, kind=kind):
                    table.setdefault(edge.source_id, []).append(nodes[edge.target_id])
            candidates, counterevidence, assessments = [], [], []
            for invariant in self.semantics.resolve_concurrency_invariants():
                operations = [node for node in nodes.values()
                              if node.attributes.get("entity") == invariant.entity
                              and node.attributes.get("operation") == invariant.operation]
                for operation in operations:
                    reads = links[EdgeKind.READS_RESOURCE].get(operation.id, [])
                    checks = links[EdgeKind.CHECKS_RESOURCE].get(operation.id, [])
                    writes = links[EdgeKind.WRITES_RESOURCE].get(operation.id, [])
                    transactions = links[EdgeKind.IN_TRANSACTION].get(operation.id, [])
                    resource_ids = {row.id for row in (*reads, *checks, *writes)}
                    same_resource = len(resource_ids) == 1 and bool(reads and checks and writes)
                    controls = tuple(operation.attributes.get("concurrency_controls", ()))
                    accepted = tuple(sorted(set(controls) & invariant.accepted_controls))
                    isolation = operation.attributes.get("isolation_level")
                    if isolation in invariant.accepted_isolation_levels:
                        accepted = tuple(dict.fromkeys((*accepted, f"isolation:{isolation}")))
                    violations, unknowns = [], []
                    if not reads:
                        unknowns.append("resource read fact missing")
                    if not checks:
                        unknowns.append("resource check fact missing")
                    if not writes:
                        unknowns.append("resource write fact missing")
                    if len(resource_ids) > 1:
                        violations.append("read-check-write targets differ")
                    if invariant.requires_transaction and not transactions:
                        violations.append("transaction boundary missing")
                    if transactions and isolation is None:
                        unknowns.append("runtime isolation level unknown")
                    if not accepted:
                        violations.append("atomic concurrency control missing")
                    path_nodes = tuple(dict.fromkeys(
                        (*(row.id for row in reads), *(row.id for row in checks), operation.id,
                         *(row.id for row in writes), *(row.id for row in transactions))))
                    resource_id = next(iter(resource_ids)) if len(resource_ids) == 1 else None
                    evidence = RaceTransactionEvidence(
                        invariant.id, operation.id, resource_id, tuple(row.id for row in reads),
                        tuple(row.id for row in checks), tuple(row.id for row in writes),
                        same_resource, tuple(row.id for row in transactions), isolation, controls,
                        accepted, tuple(violations), tuple(unknowns),
                        tuple(nodes[item].location for item in path_nodes))
                    assessments.append(evidence)
                    if same_resource and not violations and not unknowns:
                        counterevidence.append(evidence)
                        continue
                    rule = f"race-transaction:{invariant.id}"
                    entry = path_nodes[0] if path_nodes else operation.id
                    candidate_path = path_nodes or (operation.id,)
                    if candidate_path[-1] != operation.id:
                        candidate_path = (*candidate_path, operation.id)
                    candidates.append(Candidate(
                        candidate_identity(rule, snapshot_id, entry, operation.id,
                                           resource_id or operation.id),
                        CandidateKind.RACE_TRANSACTION, rule, "race-transaction", self.VERSION,
                        snapshot_id, entry, operation.id, resource_id or operation.id,
                        candidate_path, tuple(nodes[item].location for item in candidate_path),
                        "concurrency", (), accepted, tuple(violations), tuple(unknowns),
                        tuple(dict.fromkeys(nodes[item].origin for item in candidate_path))))
            _, peak = tracemalloc.get_traced_memory()
            metrics = {"snapshot_id": snapshot_id, "operations": len(assessments),
                       "candidates": len(candidates), "defended": len(counterevidence),
                       "unknown_rate": (sum(bool(row.unknowns) for row in assessments) /
                                        len(assessments) if assessments else 0.0),
                       "elapsed_ms": round((time.perf_counter() - started) * 1000, 3),
                       "peak_memory_bytes": peak}
            return RaceTransactionAnalysisResult(tuple(candidates), tuple(counterevidence),
                                                 tuple(assessments), metrics)
        finally:
            if owns_trace:
                tracemalloc.stop()
