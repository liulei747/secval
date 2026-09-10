"""Run opaque authorization fact cases without loading the external oracle."""

import argparse
import json
from pathlib import Path

from secval.analyzers import AuthorizationEngine
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


def _contract():
    return ControlContract("blind.authorization", 1, "policy.check",
                           frozenset({FlowState("authorization", "unchecked")}),
                           frozenset({FlowState("authorization", "checked")}),
                           frozenset({"authorization"}), "relation holds", FailureBehavior.THROWS,
                           ModelStatus.VERIFIED, ("blind-policy",), "blind-suite-maintainer")


def run_suite(suite):
    results, metrics = [], []
    for case in suite["cases"]:
        snapshot, store, nodes = "authorization:" + case["id"], InMemoryFactStore(), {}
        for index, raw in enumerate(case["nodes"], 1):
            node = FactNode(stable_node_id("java", NodeKind.RESOURCE, raw["id"]),
                            NodeKind.RESOURCE, snapshot, SourceLocation("src/Feature.java", index),
                            "blind-auth-facts", "1", FactConfidence.PARSER_PROVEN,
                            dict(raw.get("attributes", {})))
            store.add_node(node)
            nodes[raw["id"]] = node
        operation = nodes["operation"]
        operation.attributes["principal_node_id"] = nodes["principal"].id
        operation.attributes["resource_node_id"] = nodes["resource"].id
        operation.attributes["guarded_value_id"] = nodes["resource"].id
        if "guard" in nodes:
            nodes["guard"].attributes["checked_value_ids"] = (nodes["resource"].id,)
        for index, pair in enumerate(case["edges"]):
            source, target = nodes[pair[0]], nodes[pair[1]]
            discriminator = str(index)
            store.add_edge(FactEdge(
                stable_edge_id(snapshot, EdgeKind.FLOWS_TO, source.id, target.id, discriminator),
                EdgeKind.FLOWS_TO, snapshot, source.id, target.id, "blind-auth-facts",
                FactConfidence.PARSER_PROVEN, target.location, {"discriminator": discriminator}))
        registry = SemanticRegistry()
        if case.get("contract"):
            registry.register_control(_contract())
        result = AuthorizationEngine(store, registry).analyze(snapshot)
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
                        default="benchmarks/kernel_quality/blind/authorization-cases.json")
    args = parser.parse_args()
    suite = json.loads(Path(args.suite).read_text(encoding="utf-8"))
    results, metrics = run_suite(suite)
    print(json.dumps({"results": results, "metrics": metrics}, ensure_ascii=False))


if __name__ == "__main__":
    main()
