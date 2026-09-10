"""Run opaque configuration cases without loading the external oracle."""

import argparse
import json
from pathlib import Path

from secval.analyzers import ConfigurationEngine
from secval.facts import InMemoryFactStore
from secval.frontends import ConfigFactBuilder, ConfigLayer
from secval.semantics import ConfigurationPolicy, ModelStatus, SemanticRegistry


def _policy():
    return ConfigurationPolicy(
        "blind.configuration", 1, "service.mode", frozenset({"active"}),
        "network.scope", frozenset({"public"}), "access.control",
        frozenset({"required"}), "Runtime.launch()", "admin-endpoint",
        ModelStatus.VERIFIED, ("blind-policy",), "blind-suite-maintainer")


def run_suite(suite):
    results, metrics = [], []
    for case in suite["cases"]:
        snapshot, store = "configuration:" + case["id"], InMemoryFactStore()
        layers = [ConfigLayer(row["name"], row["format"], row["path"], row["content"],
                              row["precedence"], row.get("profile")) for row in case["layers"]]
        ConfigFactBuilder().build(store, snapshot, layers,
                                  deployment=case.get("deployment"))
        registry = SemanticRegistry(configuration_policies=[_policy()])
        result = ConfigurationEngine(store, registry).analyze(snapshot)
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
                        default="benchmarks/kernel_quality/blind/configuration-cases.json")
    args = parser.parse_args()
    results, metrics = run_suite(json.loads(Path(args.suite).read_text(encoding="utf-8")))
    print(json.dumps({"results": results, "metrics": metrics}, ensure_ascii=False))


if __name__ == "__main__":
    main()
