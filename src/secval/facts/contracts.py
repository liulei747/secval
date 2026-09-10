"""Minimal fact contracts; these types contain code facts, never vulnerability verdicts."""

import hashlib
import json
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol


class FactConfidence(StrEnum):
    PARSER_PROVEN = "parser_proven"
    RESOLVED = "resolved"
    CONSERVATIVE = "conservative"


class NodeKind(StrEnum):
    FILE = "file"
    TYPE = "type"
    METHOD = "method"
    PARAMETER = "parameter"
    CALL = "call"
    VALUE = "value"
    CONFIG = "config"
    DEPENDENCY = "dependency"
    RESOURCE = "resource"
    STATE = "state"


class EdgeKind(StrEnum):
    FLOWS_TO = "FLOWS_TO"
    CALLS = "CALLS"
    ARGUMENT_TO_PARAMETER = "ARGUMENT_TO_PARAMETER"
    RETURNS_TO = "RETURNS_TO"
    DEFINES_USES = "DEFINES_USES"
    CONTROLS = "CONTROLS"
    OVERRIDES = "OVERRIDES"
    CONFIGURES = "CONFIGURES"
    EXPOSES = "EXPOSES"
    PROTECTS = "PROTECTS"
    READS_STATE = "READS_STATE"
    WRITES_STATE = "WRITES_STATE"
    CAUSES_EFFECT = "CAUSES_EFFECT"
    READS_RESOURCE = "READS_RESOURCE"
    CHECKS_RESOURCE = "CHECKS_RESOURCE"
    WRITES_RESOURCE = "WRITES_RESOURCE"
    IN_TRANSACTION = "IN_TRANSACTION"


@dataclass(frozen=True, slots=True)
class SourceLocation:
    path: str
    start_line: int
    end_line: int | None = None
    start_column: int | None = None
    end_column: int | None = None

    def __post_init__(self):
        if not self.path or self.path.startswith(("/", "\\")) or ".." in self.path.replace("\\", "/").split("/"):
            raise ValueError("事实源码位置必须是快照内相对路径")
        end_line = self.start_line if self.end_line is None else self.end_line
        if self.start_line < 1 or end_line < self.start_line:
            raise ValueError("事实源码行范围不合法")
        object.__setattr__(self, "end_line", end_line)


def stable_node_id(language, kind, symbol):
    """Build a snapshot-independent identity; snapshot scope is stored separately."""
    values = (language, str(kind), symbol)
    if any(not isinstance(value, str) or not value.strip() for value in values):
        raise ValueError("稳定节点ID字段不能为空")
    return ":".join(value.strip() for value in values)


def stable_edge_id(snapshot_id, kind, source_id, target_id, discriminator=""):
    values = (snapshot_id, str(kind), source_id, target_id, discriminator)
    encoded = json.dumps(values, ensure_ascii=False, separators=(",", ":"))
    return "edge:" + hashlib.sha256(encoded.encode()).hexdigest()[:24]


@dataclass(frozen=True, slots=True)
class FactNode:
    id: str
    kind: NodeKind
    snapshot_id: str
    location: SourceLocation
    origin: str
    parser_version: str
    confidence: FactConfidence
    attributes: dict = field(default_factory=dict)

    def __post_init__(self):
        for name in ("id", "snapshot_id", "origin", "parser_version"):
            if not isinstance(getattr(self, name), str) or not getattr(self, name).strip():
                raise ValueError(f"FactNode.{name}不能为空")


@dataclass(frozen=True, slots=True)
class FactEdge:
    id: str
    kind: EdgeKind
    snapshot_id: str
    source_id: str
    target_id: str
    origin: str
    confidence: FactConfidence
    location: SourceLocation
    attributes: dict = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ParseGap:
    id: str
    snapshot_id: str
    category: str
    reason: str
    location: SourceLocation
    origin: str
    parser_version: str
    symbol: str | None = None


class FactReader(Protocol):
    def nodes(self, snapshot_id: str) -> tuple[FactNode, ...]: ...

    def node(self, snapshot_id: str, node_id: str) -> FactNode | None: ...

    def edges(self, snapshot_id: str, *, kind: EdgeKind | None = None) -> tuple[FactEdge, ...]: ...

    def gaps(self, snapshot_id: str) -> tuple[ParseGap, ...]: ...


class InMemoryFactStore:
    """Reference store used to enforce the contract before frontend adapters land."""

    def __init__(self):
        self._nodes = {}
        self._edges = {}
        self._gaps = {}

    def add_node(self, node):
        key = (node.snapshot_id, node.id)
        existing = self._nodes.get(key)
        if existing is not None and existing != node:
            raise ValueError("同一快照中的稳定节点ID发生冲突")
        self._nodes[key] = node

    def add_edge(self, edge):
        source = self._nodes.get((edge.snapshot_id, edge.source_id))
        target = self._nodes.get((edge.snapshot_id, edge.target_id))
        if source is None or target is None:
            raise ValueError("事实边端点必须存在于同一快照")
        expected = stable_edge_id(edge.snapshot_id, edge.kind, edge.source_id, edge.target_id,
                                  str(edge.attributes.get("discriminator", "")))
        if edge.id != expected:
            raise ValueError("事实边ID与稳定身份不一致")
        key = (edge.snapshot_id, edge.id)
        existing = self._edges.get(key)
        if existing is not None and existing != edge:
            raise ValueError("同一快照中的稳定边ID发生冲突")
        self._edges[key] = edge

    def add_gap(self, gap):
        key = (gap.snapshot_id, gap.id)
        existing = self._gaps.get(key)
        if existing is not None and existing != gap:
            raise ValueError("同一快照中的解析缺口ID发生冲突")
        self._gaps[key] = gap

    def node(self, snapshot_id, node_id):
        return self._nodes.get((snapshot_id, node_id))

    def nodes(self, snapshot_id):
        return tuple(node for (scope, _), node in self._nodes.items() if scope == snapshot_id)

    def edges(self, snapshot_id, *, kind=None):
        return tuple(edge for (scope, _), edge in self._edges.items()
                     if scope == snapshot_id and (kind is None or edge.kind == kind))

    def gaps(self, snapshot_id):
        return tuple(gap for (scope, _), gap in self._gaps.items() if scope == snapshot_id)

    def coverage(self, snapshot_id):
        nodes = [node for (scope, _), node in self._nodes.items() if scope == snapshot_id]
        gaps = list(self.gaps(snapshot_id))
        categories = {}
        for gap in gaps:
            categories[gap.category] = categories.get(gap.category, 0) + 1
        return {"snapshot_id": snapshot_id, "fact_nodes": len(nodes),
                "fact_edges": len(self.edges(snapshot_id)), "parse_gaps": len(gaps),
                "gap_categories": dict(sorted(categories.items())),
                "complete": bool(nodes) and not gaps}

    def invalidate_snapshot(self, snapshot_id):
        """Remove one exact snapshot after its source or dependency closure changes."""
        removed = {"nodes": 0, "edges": 0, "gaps": 0}
        for collection, name in ((self._edges, "edges"), (self._nodes, "nodes"),
                                 (self._gaps, "gaps")):
            keys = [key for key in collection if key[0] == snapshot_id]
            for key in keys:
                del collection[key]
            removed[name] = len(keys)
        return removed
