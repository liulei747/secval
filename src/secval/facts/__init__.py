"""[SECVAL-LEGACY-EXPERIMENTAL]
本模块属于安全分析内核（B腿），当前不参与生产审计，仅作研究路径保留。
已确认问题：9 种 EdgeKind 缺少生产者，导致多个分析器空转；
其 EFFECTS 规则表与 A 腿 _SINK_RULES 为同一批硬编码字面量。
详见 docs/leg-b-status.md。
"""
"""Stable, snapshot-scoped facts consumed by security analyzers."""

from secval.facts.adapters import (
    JoernFactAdapter,
    Neo4jFactAdapter,
    TreeSitterFactAdapter,
)
from secval.facts.contracts import (
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

__all__ = [
    "EdgeKind", "FactConfidence", "FactEdge", "FactNode", "InMemoryFactStore",
    "JoernFactAdapter", "Neo4jFactAdapter", "NodeKind", "ParseGap", "SourceLocation",
    "TreeSitterFactAdapter", "stable_edge_id", "stable_node_id",
]
