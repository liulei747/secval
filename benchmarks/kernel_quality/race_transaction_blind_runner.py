"""Run opaque race/transaction cases without loading their oracle."""

import argparse
import json
from pathlib import Path

from secval.analyzers import RaceTransactionEngine
from secval.facts import (
    EdgeKind,
    FactConfidence,
    FactEdge,
    FactNode,
    InMemoryFactStore,
    NodeKind,
    SourceLocation,
    stable_edge_id,
    stable_node_id,
)
from secval.semantics import ConcurrencyInvariant, InvariantStatus, SemanticRegistry


def _node(store, snapshot, name, kind=NodeKind.RESOURCE, **attributes):
    row = FactNode(stable_node_id("blind", kind, name), kind, snapshot,
                   SourceLocation("src/Counter.java", len(store.nodes(snapshot)) + 1),
                   "blind-race-facts", "1", FactConfidence.PARSER_PROVEN, attributes)
    store.add_node(row)
    return row


def _edge(store, snapshot, source, target, kind):
    discriminator = f"{kind}:{target.id}"
    store.add_edge(FactEdge(stable_edge_id(snapshot, kind, source.id, target.id, discriminator),
                            kind, snapshot, source.id, target.id, "blind-race-facts",
                            FactConfidence.RESOLVED, target.location,
                            {"discriminator": discriminator}))


def run_suite(suite):
    results, metrics = [], []
    for case in suite["cases"]:
        snapshot, store = "race:" + case["id"], InMemoryFactStore()
        operation = _node(store, snapshot, "operation", NodeKind.METHOD, entity="Counter",
                          operation="consume", concurrency_controls=case["controls"],
                          isolation_level=case.get("isolation"))
        resource = _node(store, snapshot, "resource")
        for kind in (EdgeKind.READS_RESOURCE, EdgeKind.CHECKS_RESOURCE,
                     EdgeKind.WRITES_RESOURCE):
            _edge(store, snapshot, operation, resource, kind)
        if case["transaction"]:
            transaction = _node(store, snapshot, "transaction", NodeKind.METHOD)
            _edge(store, snapshot, operation, transaction, EdgeKind.IN_TRANSACTION)
        registry = SemanticRegistry(concurrency_invariants=[ConcurrencyInvariant(
            "blind.race", 1, "Counter", "consume", frozenset({"atomic"}),
            frozenset({"serializable"}), True, InvariantStatus.VERIFIED,
            ("blind-invariant",), "human", "blind-suite-maintainer")])
        result = RaceTransactionEngine(store, registry).analyze(snapshot)
        if result.counterevidence:
            outcome = "refuted"
        elif result.candidates and result.candidates[0].unknowns:
            outcome = "inconclusive"
        else:
            outcome = "supported"
        results.append({"id": case["id"], "outcome": outcome})
        metrics.append(result.metrics)
    return results, metrics


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("suite", nargs="?",
                        default="benchmarks/kernel_quality/blind/race-transaction-cases.json")
    args = parser.parse_args()
    results, metrics = run_suite(json.loads(Path(args.suite).read_text(encoding="utf-8")))
    print(json.dumps({"results": results, "metrics": metrics}, ensure_ascii=False))


if __name__ == "__main__":
    main()
