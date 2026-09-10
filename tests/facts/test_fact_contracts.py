import pytest

from secval.facts import (
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

LOCATION = SourceLocation("src/OrderService.java", 8, 9)


def node(snapshot, symbol):
    return FactNode(stable_node_id("java", NodeKind.METHOD, symbol), NodeKind.METHOD,
                    snapshot, LOCATION, "tree-sitter-java", "0.23.5",
                    FactConfidence.PARSER_PROVEN)


def test_repeated_build_has_stable_ids_and_snapshot_isolation():
    first = node("snapshot-1", "demo.OrderService.load(java.lang.String)")
    repeated = node("snapshot-1", "demo.OrderService.load(java.lang.String)")
    second_snapshot = node("snapshot-2", "demo.OrderService.load(java.lang.String)")
    store = InMemoryFactStore()
    store.add_node(first)
    store.add_node(repeated)
    store.add_node(second_snapshot)
    assert first.id == repeated.id == second_snapshot.id
    assert store.node("snapshot-1", first.id).snapshot_id == "snapshot-1"
    assert store.node("snapshot-2", first.id).snapshot_id == "snapshot-2"


def test_edges_require_both_endpoints_in_same_snapshot():
    source = node("snapshot-1", "demo.Controller.get()")
    target = node("snapshot-2", "demo.Service.get()")
    store = InMemoryFactStore()
    store.add_node(source)
    store.add_node(target)
    edge_id = stable_edge_id("snapshot-1", EdgeKind.CALLS, source.id, target.id)
    edge = FactEdge(edge_id, EdgeKind.CALLS, "snapshot-1", source.id, target.id,
                    "joern", FactConfidence.RESOLVED, LOCATION)
    with pytest.raises(ValueError, match="同一快照"):
        store.add_edge(edge)


def test_parse_gaps_are_queryable_instead_of_becoming_absence():
    store = InMemoryFactStore()
    gap = ParseGap("gap:reflection:1", "snapshot-1", "dynamic_dispatch",
                   "反射目标无法静态解析", LOCATION, "joern", "4.0", "Class.forName")
    store.add_gap(gap)
    assert store.gaps("snapshot-1") == (gap,)
    assert store.gaps("snapshot-2") == ()


def test_source_location_rejects_paths_outside_snapshot():
    with pytest.raises(ValueError):
        SourceLocation("../outside.java", 1)


def test_snapshot_invalidation_removes_only_exact_snapshot():
    store = InMemoryFactStore()
    store.add_node(node("snapshot-1", "demo.One.run()"))
    other = node("snapshot-2", "demo.Two.run()")
    store.add_node(other)
    gap = ParseGap("gap:1", "snapshot-1", "missing_dependency", "missing", LOCATION,
                   "joern", "4.0")
    store.add_gap(gap)
    assert store.coverage("snapshot-1")["complete"] is False
    assert store.invalidate_snapshot("snapshot-1") == {"nodes": 1, "edges": 0, "gaps": 1}
    assert store.node("snapshot-2", other.id) == other
    assert store.coverage("snapshot-1")["fact_nodes"] == 0
