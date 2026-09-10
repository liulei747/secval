"""Run opaque state-transition cases without loading their oracle."""

import argparse
import json
from pathlib import Path

from secval.analyzers import StateMachineEngine
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
from secval.semantics import InvariantStatus, SemanticRegistry, StateTransitionInvariant


def _node(store, snapshot, name, kind, **attributes):
    row = FactNode(stable_node_id("blind", kind, name), kind, snapshot,
                   SourceLocation("src/Process.java", len(store.nodes(snapshot)) + 1),
                   "blind-state-facts", "1", FactConfidence.PARSER_PROVEN, attributes)
    store.add_node(row)
    return row


def _edge(store, snapshot, source, target, kind):
    discriminator = f"{kind}:{target.id}"
    store.add_edge(FactEdge(stable_edge_id(snapshot, kind, source.id, target.id, discriminator),
                            kind, snapshot, source.id, target.id, "blind-state-facts",
                            FactConfidence.RESOLVED, target.location,
                            {"discriminator": discriminator}))


def run_suite(suite):
    results, metrics = [], []
    for case in suite["cases"]:
        snapshot, store = "state:" + case["id"], InMemoryFactStore()
        operation = _node(store, snapshot, "operation", NodeKind.METHOD,
                          entity="Dispatch", operation="release",
                          preconditions=case["conditions"],
                          initial_state_known=case["initial_known"])
        if "from" in case:
            source = _node(store, snapshot, "source", NodeKind.STATE, state=case["from"])
            _edge(store, snapshot, operation, source, EdgeKind.READS_STATE)
        target = _node(store, snapshot, "target", NodeKind.STATE, state=case["to"])
        _edge(store, snapshot, operation, target, EdgeKind.WRITES_STATE)
        for index, effect_name in enumerate(case["effects"]):
            effect = _node(store, snapshot, f"effect-{index}", NodeKind.RESOURCE,
                           effect=effect_name)
            _edge(store, snapshot, operation, effect, EdgeKind.CAUSES_EFFECT)
        registry = SemanticRegistry(state_invariants=[StateTransitionInvariant(
            "blind.state", 1, "Dispatch", "release", frozenset({"queued"}),
            frozenset({"released"}), frozenset({"authorized"}), False,
            frozenset({"journal"}), InvariantStatus.VERIFIED, ("blind-invariant",),
            "human", "blind-suite-maintainer")])
        result = StateMachineEngine(store, registry).analyze(snapshot)
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
                        default="benchmarks/kernel_quality/blind/state-machine-cases.json")
    args = parser.parse_args()
    results, metrics = run_suite(json.loads(Path(args.suite).read_text(encoding="utf-8")))
    print(json.dumps({"results": results, "metrics": metrics}, ensure_ascii=False))


if __name__ == "__main__":
    main()
