from types import SimpleNamespace

from secval.frontends import FactSnapshotBuilder


def chunk(name, path, line):
    return SimpleNamespace(symbol_names=[name], chunk_type="method", relative_path=path,
                           start_line=line, end_line=line + 2, symbol_id=name)


def test_builder_integrates_tree_sitter_neo4j_joern_and_visible_gaps():
    chunks = [
        chunk("sample.Entry.read(java.lang.String)", "src/Entry.java", 4),
        chunk("sample.Store.load(java.lang.String)", "src/Store.java", 9),
    ]
    graph_calls = [{"caller": chunks[0].symbol_names[0], "callee": chunks[1].symbol_names[0],
                    "caller_path": "src/Entry.java", "call_line": 6,
                    "resolution_strategy": "JOERN_CPG"},
                   {"caller": chunks[0].symbol_names[0], "callee": "external.Policy.check()",
                    "caller_path": "src/Entry.java", "call_line": 5}]
    paths = [{"steps": [
        {"node_type": "METHOD_PARAMETER_IN", "path": "src/Entry.java", "line": 4},
        {"node_type": "CALL", "path": "src/Store.java", "line": 10},
    ]}]
    store = FactSnapshotBuilder("snapshot-1", "java", "0.23.5").build(
        chunks, graph_calls=graph_calls, joern_paths=paths,
        parse_failures=[("src/Broken.java", "syntax error")],
        dynamic_calls=[{"path": "src/Proxy.java", "line": 7, "name": "invoke"}],
    )
    coverage = store.coverage("snapshot-1")
    assert coverage == {"snapshot_id": "snapshot-1", "fact_nodes": 4, "fact_edges": 2,
                        "parse_gaps": 3, "gap_categories": {
                            "dynamic_dispatch": 1, "missing_dependency": 1, "parse_failure": 1},
                        "complete": False}


def test_rebuild_invalidates_old_snapshot_facts_before_materialization():
    builder = FactSnapshotBuilder("snapshot-1", "java", "0.23.5")
    old = chunk("sample.Old.run()", "src/Old.java", 1)
    new = chunk("sample.New.run()", "src/New.java", 1)
    store = builder.build([old])
    old_id = next(iter(store._nodes.values())).id
    builder.rebuild([new])
    assert store.node("snapshot-1", old_id) is None
    assert store.coverage("snapshot-1")["fact_nodes"] == 1
