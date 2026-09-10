"""Adapters from existing Tree-sitter, Joern, and Neo4j result records to facts."""

from pathlib import PurePosixPath

from secval.facts.contracts import (
    EdgeKind,
    FactConfidence,
    FactEdge,
    FactNode,
    NodeKind,
    ParseGap,
    SourceLocation,
    stable_edge_id,
    stable_node_id,
)


def _relative_path(value):
    normalized = str(value or "").replace("\\", "/")
    marker = "/src/"
    if marker in normalized and normalized.startswith("/"):
        normalized = "src/" + normalized.split(marker, 1)[1]
    path = PurePosixPath(normalized)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise ValueError("frontend返回了快照外路径")
    return path.as_posix()


class TreeSitterFactAdapter:
    def __init__(self, snapshot_id, language, parser_version):
        self.snapshot_id = snapshot_id
        self.language = language
        self.parser_version = parser_version

    def symbols(self, chunks):
        facts = []
        kind_by_chunk = {"class": NodeKind.TYPE, "interface": NodeKind.TYPE,
                         "enum": NodeKind.TYPE, "method": NodeKind.METHOD,
                         "function": NodeKind.METHOD, "field": NodeKind.VALUE,
                         "constant": NodeKind.VALUE}
        for chunk in chunks:
            names = list(getattr(chunk, "symbol_names", []) or [])
            if not names:
                continue
            kind = kind_by_chunk.get(getattr(chunk, "chunk_type", ""), NodeKind.VALUE)
            location = SourceLocation(_relative_path(chunk.relative_path), chunk.start_line,
                                      chunk.end_line)
            for name in names:
                facts.append(FactNode(
                    stable_node_id(self.language, kind, name), kind, self.snapshot_id, location,
                    f"tree-sitter-{self.language}", self.parser_version,
                    FactConfidence.PARSER_PROVEN,
                    {"legacy_symbol_id": str(getattr(chunk, "symbol_id", "") or ""),
                     "signature": name},
                ))
        return facts

    def parse_failure(self, path, reason):
        relative = _relative_path(path)
        gap_id = stable_node_id(self.language, "parse_gap", relative)
        return ParseGap(gap_id, self.snapshot_id, "parse_failure", str(reason),
                        SourceLocation(relative, 1), f"tree-sitter-{self.language}",
                        self.parser_version)


class Neo4jFactAdapter:
    def __init__(self, snapshot_id):
        self.snapshot_id = snapshot_id

    def call_edge(self, row, nodes_by_symbol):
        caller, callee = row.get("caller"), row.get("callee")
        source = nodes_by_symbol.get(caller)
        target = nodes_by_symbol.get(callee)
        line = row.get("call_line") or row.get("line") or 1
        path = row.get("caller_path") or row.get("path")
        if source is None or target is None:
            missing = callee if target is None else caller
            return ParseGap(
                stable_node_id("graph", "parse_gap", f"neo4j-call:{caller}:{callee}:{line}"),
                self.snapshot_id, "missing_dependency", f"调用端点未解析: {missing}",
                SourceLocation(_relative_path(path), line), "neo4j", "code-graph-v1", missing,
            )
        confidence = (FactConfidence.RESOLVED if row.get("resolution_strategy") == "JOERN_CPG"
                      else FactConfidence.CONSERVATIVE)
        attributes = {"discriminator": f"{_relative_path(path)}:{line}",
                      "resolution_strategy": row.get("resolution_strategy")}
        edge_id = stable_edge_id(self.snapshot_id, EdgeKind.CALLS, source.id, target.id,
                                 attributes["discriminator"])
        return FactEdge(edge_id, EdgeKind.CALLS, self.snapshot_id, source.id, target.id,
                        "neo4j", confidence, SourceLocation(_relative_path(path), line), attributes)


class JoernFactAdapter:
    def __init__(self, snapshot_id, parser_version="cpg"):
        self.snapshot_id = snapshot_id
        self.parser_version = parser_version

    def data_path(self, path, path_number=0):
        nodes, edges = [], []
        previous = None
        for index, step in enumerate(path.get("steps", [])):
            relative = _relative_path(step.get("path"))
            line = int(step.get("line") or 1)
            symbol = f"{relative}:{line}:{step.get('node_type')}:{path_number}:{index}"
            node = FactNode(stable_node_id("cpg", NodeKind.VALUE, symbol), NodeKind.VALUE,
                            self.snapshot_id, SourceLocation(relative, line), "joern",
                            self.parser_version, FactConfidence.RESOLVED,
                            {"cpg_label": step.get("node_type")})
            nodes.append(node)
            if previous is not None:
                discriminator = f"path-{path_number}-step-{index}"
                edge_id = stable_edge_id(self.snapshot_id, EdgeKind.DEFINES_USES,
                                         previous.id, node.id, discriminator)
                edges.append(FactEdge(
                    edge_id, EdgeKind.DEFINES_USES, self.snapshot_id, previous.id, node.id,
                    "joern", FactConfidence.RESOLVED, node.location,
                    {"discriminator": discriminator},
                ))
            previous = node
        return nodes, edges

    def unknown_dynamic_call(self, row):
        relative = _relative_path(row.get("path"))
        line = int(row.get("line") or 1)
        symbol = row.get("callee_full_name") or row.get("name") or "<unknown>"
        gap_id = stable_node_id("cpg", "parse_gap", f"dynamic:{relative}:{line}:{symbol}")
        return ParseGap(gap_id, self.snapshot_id, "dynamic_dispatch",
                        f"Joern无法唯一解析动态调用: {symbol}",
                        SourceLocation(relative, line), "joern", self.parser_version, symbol)
