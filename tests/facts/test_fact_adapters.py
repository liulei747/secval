from types import SimpleNamespace

from secval.facts import (
    EdgeKind,
    JoernFactAdapter,
    Neo4jFactAdapter,
    ParseGap,
    TreeSitterFactAdapter,
)


def chunk(name, path="src/OrderService.java"):
    return SimpleNamespace(symbol_names=[name], chunk_type="method", relative_path=path,
                           start_line=4, end_line=8, symbol_id="legacy-1")


def test_tree_sitter_adapter_emits_stable_located_symbols_and_parse_gaps():
    adapter = TreeSitterFactAdapter("snapshot-1", "java", "0.23.5")
    first = adapter.symbols([chunk("demo.OrderService.load(java.lang.String)")])
    repeated = adapter.symbols([chunk("demo.OrderService.load(java.lang.String)")])
    assert first == repeated
    assert first[0].location.path == "src/OrderService.java"
    assert adapter.parse_failure("src/Broken.java", "syntax").category == "parse_failure"


def test_neo4j_adapter_rejects_unresolved_endpoint_as_visible_gap():
    adapter = Neo4jFactAdapter("snapshot-1")
    source = TreeSitterFactAdapter("snapshot-1", "java", "v").symbols([
        chunk("demo.Controller.get()", "src/Controller.java")])[0]
    result = adapter.call_edge({"caller": "demo.Controller.get()", "callee": "demo.Missing.get()",
                                "path": "src/Controller.java", "line": 6},
                               {"demo.Controller.get()": source})
    assert isinstance(result, ParseGap)
    assert result.category == "missing_dependency"


def test_neo4j_resolved_call_has_stable_edge_and_no_false_cross_snapshot_edge():
    tree = TreeSitterFactAdapter("snapshot-1", "java", "v")
    source, target = tree.symbols([
        chunk("demo.Controller.get()", "src/Controller.java"),
        chunk("demo.Service.get()", "src/Service.java"),
    ])
    row = {"caller": "demo.Controller.get()", "callee": "demo.Service.get()",
           "caller_path": "src/Controller.java", "call_line": 6,
           "resolution_strategy": "JOERN_CPG"}
    adapter = Neo4jFactAdapter("snapshot-1")
    first = adapter.call_edge(row, {"demo.Controller.get()": source,
                                    "demo.Service.get()": target})
    repeated = adapter.call_edge(row, {"demo.Controller.get()": source,
                                       "demo.Service.get()": target})
    assert first == repeated
    assert first.kind == EdgeKind.CALLS


def test_joern_adapter_outputs_structured_interprocedural_path():
    path = {"steps": [
        {"node_type": "METHOD_PARAMETER_IN", "path": "/input/src/Controller.java", "line": 8},
        {"node_type": "CALL", "path": "/input/src/Service.java", "line": 13},
        {"node_type": "CALL", "path": "/input/src/Repository.java", "line": 21},
    ]}
    nodes, edges = JoernFactAdapter("snapshot-1", "4.0").data_path(path)
    assert len(nodes) == 3
    assert len(edges) == 2
    assert all(edge.kind == EdgeKind.DEFINES_USES for edge in edges)
    assert [node.location.path for node in nodes] == [
        "src/Controller.java", "src/Service.java", "src/Repository.java"]


def test_joern_dynamic_dispatch_is_not_silently_dropped():
    gap = JoernFactAdapter("snapshot-1").unknown_dynamic_call(
        {"path": "src/Proxy.java", "line": 9, "name": "invoke"})
    assert gap.category == "dynamic_dispatch"
