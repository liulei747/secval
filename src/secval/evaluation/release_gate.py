"""[SECVAL-LEGACY-EXPERIMENTAL]
本模块属于安全分析内核（B腿），当前不参与生产审计，仅作研究路径保留。
已确认问题：9 种 EdgeKind 缺少生产者，导致多个分析器空转；
其 EFFECTS 规则表与 A 腿 _SINK_RULES 为同一批硬编码字面量。
详见 docs/leg-b-status.md。
"""
"""Release-quality thresholds and reproducible evaluation artifacts."""

import json
import platform
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path


@dataclass(frozen=True, slots=True)
class ReleaseThresholds:
    blind_path_recall: float = 0.85
    safe_control_false_positive_rate: float = 0.05
    mutation_stability: float = 0.95
    finding_evidence_completeness: float = 1.0
    unknown_explainability: float = 1.0
    duplicate_root_rate: float = 0.02
    benchmark_identifier_leaks: int = 0
    maximum_elapsed_ms: float = 100.0
    maximum_peak_memory_bytes: int = 1_048_576
    minimum_blind_cases: int = 24


@dataclass(frozen=True, slots=True)
class ReleaseMetrics:
    blind_path_recall: float
    safe_control_false_positive_rate: float
    mutation_stability: float
    finding_evidence_completeness: float
    unknown_explainability: float
    duplicate_root_rate: float
    benchmark_identifier_leaks: int
    maximum_elapsed_ms: float
    maximum_peak_memory_bytes: int
    blind_cases: int
    evaluated_scope_units: int
    baseline_scope_units: int


@dataclass(frozen=True, slots=True)
class ReleaseDecision:
    passed: bool
    failures: tuple[str, ...]
    metrics: ReleaseMetrics
    thresholds: ReleaseThresholds


def evaluate_release(metrics, thresholds=None):
    thresholds = thresholds or ReleaseThresholds()
    failures = []
    minimums = ("blind_path_recall", "mutation_stability", "finding_evidence_completeness",
                "unknown_explainability")
    maximums = ("safe_control_false_positive_rate", "duplicate_root_rate",
                "benchmark_identifier_leaks", "maximum_elapsed_ms",
                "maximum_peak_memory_bytes")
    for name in minimums:
        if getattr(metrics, name) < getattr(thresholds, name):
            failures.append(f"{name} below threshold")
    for name in maximums:
        if getattr(metrics, name) > getattr(thresholds, name):
            failures.append(f"{name} above threshold")
    if metrics.blind_cases < thresholds.minimum_blind_cases:
        failures.append("blind case count below threshold")
    if metrics.evaluated_scope_units < metrics.baseline_scope_units:
        failures.append("evaluated scope smaller than baseline")
    return ReleaseDecision(not failures, tuple(failures), metrics, thresholds)


def write_release_artifact(path, decision, *, version, configuration,
                           failed_samples=(), regression_diff=None):
    if not version or not configuration:
        raise ValueError("发布评估必须记录版本和配置")
    payload = {"schema_version": 1, "created_at": datetime.now(UTC).isoformat(),
               "version": version,
               "hardware": {"platform": platform.platform(),
                            "machine": platform.machine(), "processor": platform.processor()},
               "configuration": dict(sorted(configuration.items())),
               "decision": asdict(decision), "failed_samples": list(failed_samples),
               "regression_diff": regression_diff or {}}
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    serialized = json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2, default=str)
    destination.write_text(serialized + "\n", encoding="utf-8")
    return json.loads(serialized)
