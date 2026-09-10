"""Run opaque adjudication cases without loading their oracle."""

import argparse
import json
from pathlib import Path

from secval.adjudication import CandidateLedger, Verdict
from secval.candidates import Candidate, CandidateKind, candidate_identity
from secval.facts import SourceLocation


def run_suite(suite):
    results, metrics = [], []
    for case in suite["cases"]:
        rule = "blind:rule"
        candidate = Candidate(
            candidate_identity(rule, case["id"], "entry", "operation", "root"),
            CandidateKind.TAINT_FLOW, rule, "blind-engine", "1", case["id"], "entry",
            "operation", "root", ("entry", "operation"),
            (SourceLocation("src/Entry.java", 1), SourceLocation("src/Operation.java", 2)),
            "generic", (), (), (), tuple(case["unknowns"]), ("blind-facts",))
        ledger = CandidateLedger()
        ledger.ingest(candidate, "closure")
        try:
            verdict = Verdict.CONFIRMED if case["decision"] == "confirmed" else Verdict.DEFENDED
            ledger.append(candidate.id, verdict, "blind decision", tuple(case["evidence"]),
                          ("blind-ledger@1",), "closure",
                          all_paths_covered=case.get("all_paths_covered", False))
        except ValueError:
            pass
        current = ledger.current(candidate.id).verdict
        outcome = ({Verdict.CONFIRMED: "supported", Verdict.DEFENDED: "refuted"}
                   .get(current, "inconclusive"))
        results.append({"id": case["id"], "outcome": outcome})
        metrics.append({"events": len(ledger.events()), "chain_valid": ledger.verify_chain()})
    return results, metrics


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("suite", nargs="?",
                        default="benchmarks/kernel_quality/blind/ledger-cases.json")
    args = parser.parse_args()
    results, metrics = run_suite(json.loads(Path(args.suite).read_text(encoding="utf-8")))
    print(json.dumps({"results": results, "metrics": metrics}, ensure_ascii=False))


if __name__ == "__main__":
    main()
