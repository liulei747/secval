"""Run opaque CFG cases through GuardEngine without loading the external oracle."""

import argparse
import json
from pathlib import Path

from secval.analyzers import GuardEngine
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
from secval.semantics import (
    ControlContract,
    FailureBehavior,
    FlowState,
    ModelStatus,
    SemanticRegistry,
)


def _control():
    return ControlContract("blind.control", 1, "control.check",
                           frozenset({FlowState("authorization", "unchecked")}),
                           frozenset({FlowState("authorization", "checked")}),
                           frozenset({"authorization"}), "same resource",
                           FailureBehavior.THROWS, ModelStatus.VERIFIED,
                           ("blind-control-source",), "blind-suite-maintainer")


def run_suite(suite):
    results, metrics = [], []
    for case in suite["cases"]:
        snapshot, store, nodes = "guard:" + case["id"], InMemoryFactStore(), {}
        for index, raw in enumerate(case["nodes"], 1):
            attributes = dict(raw.get("attributes", {}))
            node = FactNode(stable_node_id("java", NodeKind.VALUE, raw["id"]), NodeKind.VALUE,
                            snapshot, SourceLocation("src/Action.java", index), "blind-cfg", "1",
                            FactConfidence.PARSER_PROVEN, attributes)
            store.add_node(node)
            nodes[raw["id"]] = node
        for index, pair in enumerate(case["edges"]):
            source, target = nodes[pair[0]], nodes[pair[1]]
            discriminator = str(index)
            store.add_edge(FactEdge(
                stable_edge_id(snapshot, EdgeKind.FLOWS_TO, source.id, target.id, discriminator),
                EdgeKind.FLOWS_TO, snapshot, source.id, target.id, "blind-cfg",
                FactConfidence.PARSER_PROVEN, target.location, {"discriminator": discriminator}))
        registry = SemanticRegistry()
        if case.get("contract"):
            registry.register_control(_control())
        analysis = GuardEngine(store, registry).analyze(snapshot)
        if analysis.counterevidence:
            outcome = "refuted"
        elif analysis.candidates and not analysis.candidates[0].unknowns:
            outcome = "supported"
        else:
            outcome = "inconclusive"
        results.append({"id": case["id"], "outcome": outcome})
        metrics.append(analysis.metrics)
    return results, metrics


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("suite", nargs="?",
                        default="benchmarks/kernel_quality/blind/guard-cases.json")
    args = parser.parse_args()
    suite = json.loads(Path(args.suite).read_text(encoding="utf-8"))
    results, metrics = run_suite(suite)
    print(json.dumps({"results": results, "metrics": metrics}, ensure_ascii=False))


if __name__ == "__main__":
    main()
