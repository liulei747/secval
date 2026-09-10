"""Run opaque fact-graph cases through TaintEngine without loading the external oracle."""

import argparse
import json
from pathlib import Path

from secval.analyzers import TaintEngine
from secval.candidates import CandidateKind
from secval.facts import (
    EdgeKind,
    FactConfidence,
    FactEdge,
    FactNode,
    InMemoryFactStore,
    NodeKind,
    ParseGap,
    SourceLocation,
    stable_edge_id,
    stable_node_id,
)
from secval.semantics import FrameworkModel, ModelKind, ModelStatus, SemanticRegistry

MODEL_TESTS = frozenset({"positive", "negative", "wrapper", "inheritance", "overload", "version"})


def _model(model_id, kind, signature):
    return FrameworkModel(model_id, 1, "java", "spring", ">=6,<7", kind, signature,
                          ModelStatus.VERIFIED, taint_kinds=frozenset({"sql"}),
                          test_coverage=MODEL_TESTS, evidence_refs=("blind-pack",),
                          approved_by="blind-suite-maintainer")


def run_suite(suite):
    results, metrics = [], []
    models = [_model("blind.source", ModelKind.SOURCE, "input"),
              _model("blind.effect", ModelKind.EFFECT, "database"),
              _model("blind.control", ModelKind.SANITIZER, "parameterized")]
    for case in suite["cases"]:
        snapshot = "blind:" + case["id"]
        store, nodes = InMemoryFactStore(), {}
        for index, raw in enumerate(case["nodes"], 1):
            node_id = stable_node_id("java", NodeKind.VALUE, raw["id"])
            node = FactNode(node_id, NodeKind.VALUE, snapshot,
                            SourceLocation(raw.get("path", "src/Feature.java"), index),
                            "blind-fact-fixture", "1", FactConfidence.PARSER_PROVEN,
                            {"signature": raw.get("signature", raw["id"]),
                             "flow_states": tuple(raw.get("flow_states", []))})
            store.add_node(node)
            nodes[raw["id"]] = node
        for index, raw in enumerate(case.get("edges", [])):
            source, target = nodes[raw[0]], nodes[raw[1]]
            discriminator = str(index)
            edge_id = stable_edge_id(snapshot, EdgeKind.DEFINES_USES,
                                     source.id, target.id, discriminator)
            store.add_edge(FactEdge(edge_id, EdgeKind.DEFINES_USES, snapshot,
                                    source.id, target.id, "blind-fact-fixture",
                                    FactConfidence.PARSER_PROVEN, target.location,
                                    {"discriminator": discriminator}))
        for index, raw in enumerate(case.get("gaps", [])):
            store.add_gap(ParseGap(f"gap:{case['id']}:{index}", snapshot, raw["category"],
                                   raw["reason"], SourceLocation(raw["path"], raw["line"]),
                                   "blind-fact-fixture", "1", raw.get("symbol")))
        analysis = TaintEngine(store, SemanticRegistry(models=list(models))).analyze(
            snapshot, language="java", framework="spring", version="6.1")
        if any(row.kind == CandidateKind.TAINT_FLOW for row in analysis.candidates):
            outcome = "supported"
        elif any(row.kind == CandidateKind.UNKNOWN_EFFECT for row in analysis.candidates):
            outcome = "inconclusive"
        elif analysis.counterevidence:
            outcome = "refuted"
        else:
            outcome = "inconclusive"
        results.append({"id": case["id"], "outcome": outcome})
        metrics.append(analysis.metrics)
    return results, metrics


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("suite", default="benchmarks/kernel_quality/blind/taint-cases.json", nargs="?")
    args = parser.parse_args()
    suite = json.loads(Path(args.suite).read_text(encoding="utf-8"))
    results, metrics = run_suite(suite)
    print(json.dumps({"results": results, "metrics": metrics}, ensure_ascii=False))


if __name__ == "__main__":
    main()
