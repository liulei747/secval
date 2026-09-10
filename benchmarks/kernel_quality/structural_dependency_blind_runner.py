"""Run opaque K9 cases without loading the external oracle."""

import argparse
import json
from pathlib import Path

from secval.analyzers import DependencyReachabilityEngine, StructuralEngine
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
from secval.frontends import ConfigFactBuilder, DependencyFactBuilder
from secval.semantics import (
    DependencyAdvisory,
    ModelStatus,
    SemanticRegistry,
    StructuralPolicy,
)


def _node(store, snapshot, name, kind=NodeKind.CALL, **attributes):
    row = FactNode(stable_node_id("blind", kind, name), kind, snapshot,
                   SourceLocation("src/Module.java", len(store.nodes(snapshot)) + 1),
                   "blind-k9-facts", "1", FactConfidence.PARSER_PROVEN, attributes)
    store.add_node(row)
    return row


def _structural(case, store, snapshot):
    _node(store, snapshot, "operation", signature=case["signature"],
          usage_context=case.get("context"), constant_value=case.get("value"))
    registry = SemanticRegistry(structural_policies=[StructuralPolicy(
        "blind.structural", 1, frozenset({"Cipher.select(java.lang.String)"}),
        frozenset({"obsolete"}), frozenset({"protected-data"}), ModelStatus.VERIFIED,
        ("blind-policy",), "blind-suite-maintainer")])
    return StructuralEngine(store, registry).analyze(snapshot)


def _dependency(case, store, snapshot):
    DependencyFactBuilder().build(store, snapshot, "requirements.txt",
                                  f"codec-core=={case['version']}", "requirements")
    call = None
    if case.get("call"):
        call = _node(store, snapshot, "operation", signature="codec.Decoder.read(byte[])")
    if case.get("reachable"):
        entry = _node(store, snapshot, "entry", NodeKind.METHOD, external_entry=True)
        discriminator = "blind-edge"
        store.add_edge(FactEdge(stable_edge_id(snapshot, EdgeKind.CALLS, entry.id, call.id,
                                               discriminator), EdgeKind.CALLS, snapshot,
                                entry.id, call.id, "blind-k9-facts", FactConfidence.RESOLVED,
                                call.location, {"discriminator": discriminator}))
    if "activation" in case:
        ConfigFactBuilder().build(store, snapshot, [], environment={"codec.mode": case["activation"]})
    registry = SemanticRegistry(dependency_advisories=[DependencyAdvisory(
        "blind.dependency", 1, "codec-core", ">=3.0,<4.0",
        frozenset({"codec.Decoder.read(byte[])"}), "codec.mode", frozenset({"on"}),
        ModelStatus.VERIFIED, ("blind-advisory",), "blind-suite-maintainer")])
    return DependencyReachabilityEngine(store, registry).analyze(snapshot)


def run_suite(suite):
    results, metrics = [], []
    for case in suite["cases"]:
        snapshot, store = "k9:" + case["id"], InMemoryFactStore()
        result = (_structural if case["engine"] == "structural" else _dependency)(
            case, store, snapshot)
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
                        default="benchmarks/kernel_quality/blind/structural-dependency-cases.json")
    args = parser.parse_args()
    results, metrics = run_suite(json.loads(Path(args.suite).read_text(encoding="utf-8")))
    print(json.dumps({"results": results, "metrics": metrics}, ensure_ascii=False))


if __name__ == "__main__":
    main()
