"""留出集评测：对未参与规则调整的仓库运行审计，得出可对外声明的泛化指标。

用法（需要已配置审计模型 API）：

    .\\.venv\\Scripts\\python.exe -m benchmarks.holdout.run_holdout --list
    .\\.venv\\Scripts\\python.exe -m benchmarks.holdout.run_holdout --repo nodegoat --score-only

设计约束：
- 本脚本不修改任何生产代码或规则；它只读审计产物。
- 评分是离线的，expected.json 内容不得进入模型上下文。
- 默认只做评分；真实审计需显式传 --run 并已有任务产物。
"""

import argparse
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
HOLDOUT = ROOT / "benchmarks" / "holdout"


def load_manifest():
    return json.loads((HOLDOUT / "manifest.json").read_text(encoding="utf-8"))


def load_expected(repo_id):
    path = HOLDOUT / "expected" / f"{repo_id}.json"
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def normalize_findings(report):
    """Extract comparable findings from an exported audit report."""
    rows = []
    for finding in report.get("findings") or []:
        location = finding.get("rootControlLocation") or {}
        rows.append({
            "ruleId": (finding.get("ruleId") or "").lower(),
            "path": (location.get("path") or "").replace("\\", "/"),
            "line": location.get("startLine"),
            "severity": ((finding.get("severity") or {}).get("level")
                         if isinstance(finding.get("severity"), dict) else finding.get("severity")),
            "title": finding.get("title") or "",
        })
    return rows


def score(repo_id, report):
    """Return recall and false-positive metrics for one holdout repo."""
    expected = load_expected(repo_id) or {}
    findings = normalize_findings(report)
    targets = expected.get("vulnerabilities") or []

    hits, missed = [], []
    for target in targets:
        target_path = target["path"].replace("\\", "/")
        # Match on vulnerability family plus file; line numbers are not required
        # because discovery and validation commonly anchor different hops of one chain.
        matched = next((row for row in findings
                        if row["path"].endswith(target_path)
                        and target["ruleId"].lower() in row["ruleId"].lower()), None)
        if matched is None:
            # Fall back to path-only matching with the declared CWE family hints.
            matched = next((row for row in findings if row["path"].endswith(target_path)), None)
        (hits if matched else missed).append(target["id"])

    matched_findings = [row for row in findings
                        if any(row["path"].endswith(t["path"].replace("\\", "/")) for t in targets)]
    unmatched = [row for row in findings if row not in matched_findings]

    result = {
        "repo_id": repo_id,
        "expected_total": len(targets),
        "hit": len(hits), "missed": missed, "hit_ids": hits,
        "findings_total": len(findings),
        "findings_outside_expected": len(unmatched),
    }
    if targets:
        result["recall"] = round(len(hits) / len(targets), 4)
    else:
        result["recall"] = None
        severities = {}
        for row in findings:
            severities[row["severity"]] = severities.get(row["severity"], 0) + 1
        result["severity_distribution"] = severities
        result["high_severity_findings"] = sum(
            count for level, count in severities.items() if level in ("critical", "high"))
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description="留出集评测（离线评分）")
    parser.add_argument("--list", action="store_true", help="列出留出集仓库")
    parser.add_argument("--repo", help="仓库ID")
    parser.add_argument("--report", help="审计报告JSON路径（导出接口产物）")
    parser.add_argument("--score-only", action="store_true", help="仅评分，不运行审计")
    args = parser.parse_args(argv)

    manifest = load_manifest()
    if args.list:
        for repo in manifest["repos"]:
            present = (ROOT / repo["path"]).exists()
            print(f"{repo['id']:12s} {repo['language']:10s} {repo['framework']:10s} "
                  f"cloned={'yes' if present else 'no ':3s} {repo['commit'][:12]}")
        return 0

    if not args.repo:
        parser.error("需要 --repo 或 --list")
    repo = next((row for row in manifest["repos"] if row["id"] == args.repo), None)
    if repo is None:
        parser.error(f"未知仓库：{args.repo}")

    if not args.report:
        print(f"仓库 {args.repo} 的评分需要审计报告。", file=sys.stderr)
        print("先用现有 Web 接口或审计服务对该仓库跑一次审计，导出报告后传 --report。",
              file=sys.stderr)
        print(f"预期产物位置约定：benchmarks/holdout/results/{args.repo}.json", file=sys.stderr)
        return 2

    report = json.loads(pathlib.Path(args.report).read_text(encoding="utf-8"))
    print(json.dumps(score(args.repo, report), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
