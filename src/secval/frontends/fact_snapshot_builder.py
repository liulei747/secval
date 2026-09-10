"""Materialize existing parser and graph outputs into one snapshot-scoped fact store."""

from secval.facts import (
    FactEdge,
    InMemoryFactStore,
    JoernFactAdapter,
    Neo4jFactAdapter,
    ParseGap,
    TreeSitterFactAdapter,
)


class FactSnapshotBuilder:
    def __init__(self, snapshot_id, language, parser_version, *, store=None):
        self.snapshot_id = snapshot_id
        self.tree_sitter = TreeSitterFactAdapter(snapshot_id, language, parser_version)
        self.neo4j = Neo4jFactAdapter(snapshot_id)
        self.joern = JoernFactAdapter(snapshot_id)
        self.store = store or InMemoryFactStore()

    def build(self, chunks, *, graph_calls=(), joern_paths=(), parse_failures=(), dynamic_calls=()):
        nodes = self.tree_sitter.symbols(chunks)
        for node in nodes:
            self.store.add_node(node)
        by_symbol = {name: node for chunk in chunks
                     for name, node in zip(getattr(chunk, "symbol_names", []) or [],
                                           self.tree_sitter.symbols([chunk]), strict=True)}
        for row in graph_calls:
            self._add(self.neo4j.call_edge(row, by_symbol))
        for number, path in enumerate(joern_paths):
            path_nodes, path_edges = self.joern.data_path(path, number)
            for node in path_nodes:
                self.store.add_node(node)
            for edge in path_edges:
                self.store.add_edge(edge)
        for path, reason in parse_failures:
            self.store.add_gap(self.tree_sitter.parse_failure(path, reason))
        for row in dynamic_calls:
            self.store.add_gap(self.joern.unknown_dynamic_call(row))
        return self.store

    def rebuild(self, *args, **kwargs):
        """Invalidate the exact snapshot before rebuilding changed source/dependency closure."""
        self.store.invalidate_snapshot(self.snapshot_id)
        return self.build(*args, **kwargs)

    def _add(self, item):
        if isinstance(item, FactEdge):
            self.store.add_edge(item)
        elif isinstance(item, ParseGap):
            self.store.add_gap(item)
        else:
            raise TypeError("frontend adapter只能产生FactEdge或ParseGap")
