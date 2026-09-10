"""Score frozen blind results using an external oracle verified by public commitments."""

import argparse
import hashlib
import json
from pathlib import Path

OUTCOMES = frozenset({"supported", "refuted", "inconclusive"})


def _canonical_hash(row):
    encoded = json.dumps(row, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def evaluate(results_path, oracle_path, commitments_path, suite_root):
    results_path = Path(results_path).resolve()
    oracle_path = Path(oracle_path).resolve()
    commitments_path = Path(commitments_path).resolve()
    suite_root = Path(suite_root).resolve()
    if oracle_path == suite_root or oracle_path.is_relative_to(suite_root):
        raise ValueError("blind oracle必须位于仓库盲测资料之外")
    results = json.loads(results_path.read_text(encoding="utf-8"))
    oracle = json.loads(oracle_path.read_text(encoding="utf-8"))
    commitments = json.loads(commitments_path.read_text(encoding="utf-8"))
    expected_ids = set(commitments)
    if {row.get("id") for row in oracle} != expected_ids:
        raise ValueError("blind oracle用例集合与承诺不一致")
    expected = {}
    for row in oracle:
        if set(row) != {"id", "outcome"} or row["outcome"] not in OUTCOMES:
            raise ValueError("blind oracle格式不合法")
        if _canonical_hash(row) != commitments[row["id"]]:
            raise ValueError("blind oracle未通过哈希承诺校验")
        expected[row["id"]] = row["outcome"]
    observed = {row.get("id"): row.get("outcome") for row in results}
    if set(observed) != expected_ids or any(value not in OUTCOMES for value in observed.values()):
        raise ValueError("blind结果必须完整覆盖承诺用例")
    correct = sum(observed[case_id] == outcome for case_id, outcome in expected.items())
    return {"cases": len(expected), "correct": correct, "accuracy": correct / len(expected),
            "passed": correct == len(expected)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("results")
    parser.add_argument("oracle")
    parser.add_argument("--commitments", default="benchmarks/kernel_quality/blind/commitments.json")
    parser.add_argument("--suite-root", default="benchmarks/kernel_quality/blind")
    args = parser.parse_args()
    print(json.dumps(evaluate(args.results, args.oracle, args.commitments, args.suite_root)))


if __name__ == "__main__":
    main()
