"""Neo4j 关系存储只接收当前索引批次，并去重文件和符号。"""

from unittest.mock import MagicMock

from secval.infrastructure.neo4j import CodeGraphStore
from secval.models.code import CodeCall, CodeChunk
from secval.models.identifiers import (
    ChunkId,
    FileId,
    RepositoryId,
    SnapshotId,
    SymbolId,
)


def test_both_call_directions_explain_unknown_and_short_type_matches():
    records = [
        {"callee": "one.Service.run", "receiver_type_full_name": "one.Service", "receiver_type": "Service"},
        {"callee": "two.Service.run", "receiver_type": "Service"},
        {"callee": "unrelated.Service.run", "receiver_type": None},
        {"callee": "legacy.run"},
    ]
    driver = MagicMock()
    driver.execute_query.return_value = (records, None, None)
    store = CodeGraphStore(driver)
    for query in (store.find_callers, store.find_callees):
        rows = query("repo", "snap", "run", "run")
        assert [row["match_basis"] for row in rows] == [
            "full_receiver_type", "short_receiver_type", "name_only", "name_only"
        ]
        assert "不能据此确认调用链" in rows[2]["match_note"]
        assert "match_basis" not in records[0]


def test_save_snapshot_deduplicates_file_and_symbol():
    driver = MagicMock()
    store = CodeGraphStore(driver)
    chunk = CodeChunk(
        ChunkId("chunk-1"), FileId("file-1"), RepositoryId("repo"), SnapshotId("snap"),
        "src/Order.java", "java", "method", "void run() {}", 3, 3,
        symbol_ids=[SymbolId("symbol-1")], symbol_names=["Order.run"],
    )

    result = store.save_snapshot("repo", "snap", "run-1", [chunk, chunk])

    assert result == {"files": 1, "symbols": 1}
    arguments = driver.execute_query.call_args.kwargs
    assert "WITH DISTINCT s" in driver.execute_query.call_args.args[0]
    assert arguments["snapshot_key"] == "repo:snap:run-1"
    assert arguments["files"] == [{"id": "file-1", "path": "src/Order.java"}]
    assert arguments["symbols"][0]["name"] == "Order.run"
    assert arguments["symbols"][0]["short_name"] == "run"
    assert arguments["symbols"][0]["owner_short_name"] == "Order"
    assert arguments["symbols"][0]["owner_full_name"] == "Order"


def test_find_symbol_is_bound_to_repository_snapshot_and_run():
    driver = MagicMock()
    driver.execute_query.return_value = ([{"name": "Order.run", "path": "src/Order.java"}], None, None)

    rows = CodeGraphStore(driver).find_symbol("repo", "snap", "run-1", "Order", 5)

    assert rows[0]["name"] == "Order.run"
    arguments = driver.execute_query.call_args.kwargs
    assert arguments["repository_id"] == "repo"
    assert arguments["snapshot_id"] == "snap"
    assert arguments["index_run_id"] == "run-1"
    assert "snapshot_id_id" not in arguments


def test_export_calls_is_bound_to_repository_snapshot_and_run():
    driver = MagicMock()
    driver.execute_query.return_value = ([{
        "caller": "App.entry", "callee": "Service.run",
        "caller_path": "src/App.java", "call_line": 12,
        "resolution_strategy": "JOERN_CPG",
    }], None, None)

    rows = CodeGraphStore(driver).export_calls("repo", "snap", "run-1")

    assert rows[0]["resolution_strategy"] == "JOERN_CPG"
    arguments = driver.execute_query.call_args.kwargs
    assert arguments["repository_id"] == "repo"
    assert arguments["snapshot_id"] == "snap"
    assert arguments["index_run_id"] == "run-1"
    assert "CALLS" in driver.execute_query.call_args.args[0]


def test_joern_call_edges_are_key_resolved_and_tree_sitter_verified():
    driver = MagicMock()
    store = CodeGraphStore(driver)
    caller = CodeChunk(
        ChunkId("chunk-1"), FileId("file-1"), RepositoryId("repo"), SnapshotId("snap"),
        "src/OrderController.java", "java", "method", "void submit() { service.run(); }", 3, 5,
        symbol_id=SymbolId("symbol-caller"), symbol_names=["App.OrderController.submit"],
        called_symbol_names=["run", "log"],
    )
    callee = CodeChunk(
        ChunkId("chunk-2"), FileId("file-1"), RepositoryId("repo"), SnapshotId("snap"),
        "src/OrderService.java", "java", "method", "void run() {}", 8, 8,
        symbol_id=SymbolId("symbol-run"), symbol_names=["App.OrderService.run"],
    )

    store.save_snapshot("repo", "snap", "run-1", [caller, callee], call_sites=[{
        "caller_full_name": "App.OrderController.submit:void()",
        "callee_full_name": "App.OrderService.run:void()", "name": "run",
        "path": "/joern-inputs/run/src/OrderController.java", "line": 3,
        "column": 10, "dispatch_type": "STATIC_DISPATCH", "signature": "void()",
        "code": "service.run()",
    }])

    callsite = driver.execute_query.call_args_list[1].kwargs["calls"][0]
    assert callsite["caller_key"] == "repo:snap:run-1:symbol-caller"
    assert callsite["callee_keys"] == ["repo:snap:run-1:symbol-run"]
    assert callsite["resolution_status"] == "RESOLVED"
    assert callsite["provenance"] == "BOTH"
    edge_query = driver.execute_query.call_args_list[2].args[0]
    assert "MATCH (callee:CodeSymbol {key: callee_key})" in edge_query
    assert "short_name" not in edge_query


def test_tree_sitter_only_call_is_preserved_without_guessing_a_target():
    driver = MagicMock()
    chunk = CodeChunk(
        ChunkId("chunk-typed"), FileId("file-1"), RepositoryId("repo"), SnapshotId("snap"),
        "src/Controller.java", "java", "method", "void submit() {}", 4, 8,
        symbol_id=SymbolId("caller-id"), symbol_names=["demo.Controller.submit()"],
        code_calls=[CodeCall("run", 6, "OrderService", 1)],
    )

    CodeGraphStore(driver).save_snapshot("repo", "snap", "run-1", [chunk])

    call = driver.execute_query.call_args_list[1].kwargs["calls"][0]
    assert call["caller_key"] == "repo:snap:run-1:caller-id"
    assert call["callee_keys"] == []
    assert call["resolution_status"] == "UNRESOLVED"
    assert call["unresolved_reason"] == "MISSING_FROM_JOERN"
    assert call["provenance"] == "TREE_SITTER"


def test_java_generic_commas_do_not_increase_parameter_count():
    driver = MagicMock()
    chunk = CodeChunk(
        ChunkId("chunk-generic"), FileId("file-1"), RepositoryId("repo"), SnapshotId("snap"),
        "src/Service.java", "java", "method", "void save(Map<K,V> values, String[] tags) {}",
        4, 4, symbol_id=SymbolId("save-id"),
        symbol_names=["demo.Service.save(Map<K,V>,String[])"],
    )

    CodeGraphStore(driver).save_snapshot("repo", "snap", "run-1", [chunk])

    symbol = driver.execute_query.call_args.kwargs["symbols"][0]
    assert symbol["owner_short_name"] == "Service"
    assert symbol["parameter_count"] == 2


def test_varargs_methods_accept_multiple_call_arguments():
    driver = MagicMock()
    varargs_method = CodeChunk(
        ChunkId("chunk-var"), FileId("file-1"), RepositoryId("repo"), SnapshotId("snap"),
        "src/S.java", "java", "method", "void log(String... parts) {}", 4, 4,
        symbol_id=SymbolId("log-id"), symbol_names=["demo.S.log(String...)"])
    caller = CodeChunk(
        ChunkId("chunk-caller"), FileId("file-1"), RepositoryId("repo"), SnapshotId("snap"),
        "src/S.java", "java", "method", "void caller() { log(\"a\", \"b\"); }", 5, 5,
        symbol_id=SymbolId("caller-id"), symbol_names=["demo.S.caller()"],
        code_calls=[CodeCall("log", 5, "S", 2)])

    CodeGraphStore(driver).save_snapshot("repo", "snap", "run-1", [varargs_method, caller])

    symbols_query = driver.execute_query.call_args_list[0]
    assert symbols_query.kwargs["symbols"][0]["varargs"] is True
    assert symbols_query.kwargs["symbols"][1]["varargs"] is False
    assert symbols_query.kwargs["symbols"][0]["required_parameter_count"] == 0


def test_python_default_parameters_allow_shorter_calls():
    driver = MagicMock()
    log_method = CodeChunk(
        ChunkId("chunk-log"), FileId("file-1"), RepositoryId("repo"), SnapshotId("snap"),
        "src/log.py", "python", "function", "def log(msg, level=1): pass", 1, 1,
        symbol_id=SymbolId("log-id"), symbol_names=["log"],
        parameter_count=2, required_parameter_count=1,
        has_default_parameters=True)
    zero_arg = CodeChunk(
        ChunkId("chunk-zero"), FileId("file-1"), RepositoryId("repo"), SnapshotId("snap"),
        "src/other.py", "python", "function", "def log(): pass", 1, 1,
        symbol_id=SymbolId("zero-id"), symbol_names=["other.log"],
        parameter_count=0, required_parameter_count=0,
        has_default_parameters=False)
    caller = CodeChunk(
        ChunkId("chunk-pcaller"), FileId("file-1"), RepositoryId("repo"), SnapshotId("snap"),
        "src/call.py", "python", "function", "def caller(): log('hi')", 1, 1,
        symbol_id=SymbolId("pcaller-id"), symbol_names=["caller"],
        code_calls=[CodeCall("log", 1, None, 1)])

    CodeGraphStore(driver).save_snapshot(
        "repo", "snap", "run-1", [log_method, zero_arg, caller])

    symbols_query = driver.execute_query.call_args_list[0]
    props = {s["name"]: s for s in symbols_query.kwargs["symbols"]}
    assert props["log"]["has_default_parameters"] is True
    assert props["log"]["python_parameter_count"] == 2
    assert props["log"]["python_required_parameter_count"] == 1
    assert props["other.log"]["has_default_parameters"] is False


def test_type_relations_are_written_from_resolved_supertypes():
    driver = MagicMock()
    type_chunk = CodeChunk(
        ChunkId("type-1"), FileId("file-1"), RepositoryId("repo"), SnapshotId("snap"),
        "src/Service.java", "java", "class", "class Service {}", 4, 8,
        symbol_ids=[SymbolId("service-id")], symbol_names=["demo.Service"],
        extends_types=["Base"], implements_types=["Greeter"],
        supertype_full_names=["demo.Base", "demo.Greeter"],
        extends_full_names=["demo.Base"],
    )

    CodeGraphStore(driver).save_snapshot("repo", "snap", "run-1", [type_chunk])

    relations_call = driver.execute_query.call_args_list[1]
    assert "MERGE (child)-[:EXTENDS]->(parent)" in relations_call.args[0]
    assert "MERGE (child)-[:IMPLEMENTS]->(parent)" in relations_call.args[0]
    assert relations_call.kwargs["relations"] == [
        {"child_symbol_id": "service-id", "parent": "demo.Base", "relation": "EXTENDS"},
        {"child_symbol_id": "service-id", "parent": "demo.Greeter", "relation": "IMPLEMENTS"},
    ]


def test_override_relations_target_ancestor_methods():
    driver = MagicMock()
    method_chunk = CodeChunk(
        ChunkId("method-1"), FileId("file-1"), RepositoryId("repo"), SnapshotId("snap"),
        "src/Service.java", "java", "method", "public void greet() {}", 5, 5,
        symbol_id=SymbolId("method-id"),
        symbol_names=["demo.Service.greet()"],
        ancestor_type_full_names=["demo.Base", "demo.Greeter"],
    )

    CodeGraphStore(driver).save_snapshot("repo", "snap", "run-1", [method_chunk])

    relations_call = driver.execute_query.call_args_list[1]
    assert "MERGE (childOwner)-[:OVERRIDES]->(ancestorMethod)" in relations_call.args[0]
    assert relations_call.kwargs["relations"] == [
        {"child_owner_symbol_id": "method-id", "child_method": "greet",
         "parameter_count": 0, "varargs": False, "ancestor_owner": "demo.Base"},
        {"child_owner_symbol_id": "method-id", "child_method": "greet",
         "parameter_count": 0, "varargs": False, "ancestor_owner": "demo.Greeter"},
    ]


def test_typescript_override_uses_the_parsed_parameter_count():
    driver = MagicMock()
    method_chunk = CodeChunk(
        ChunkId("method-ts"), FileId("file-ts"), RepositoryId("repo"),
        SnapshotId("snap"), "service.ts", "typescript", "method",
        "find(id: string): string { return id; }", 5, 5,
        symbol_id=SymbolId("method-ts-id"),
        symbol_names=["service.OrderService.find"],
        parameter_count=2,
        required_parameter_count=1,
        ancestor_type_full_names=["contracts.OrderContract"],
    )

    CodeGraphStore(driver).save_snapshot("repo", "snap", "run-ts", [method_chunk])

    symbol = driver.execute_query.call_args_list[0].kwargs["symbols"][0]
    relations_call = driver.execute_query.call_args_list[1]
    assert symbol["parameter_count"] == 2
    assert symbol["required_parameter_count"] == 1
    assert relations_call.kwargs["relations"] == [{
        "child_owner_symbol_id": "method-ts-id",
        "child_method": "find",
        "parameter_count": 2,
        "varargs": False,
        "ancestor_owner": "contracts.OrderContract",
        "required_parameter_count": 1,
        "check_varargs": True,
    }]
    query = relations_call.args[0]
    assert "ancestorMethod.required_parameter_count" in query
    assert "coalesce(ancestorMethod.varargs, false) = relation.varargs" in query


def test_find_type_relations_is_bound_and_returns_rows():
    driver = MagicMock()
    driver.execute_query.return_value = ([{
        "symbol": "demo.Service", "relation": "EXTENDS",
        "parent": "demo.Base", "path": "src/Service.java", "line": 4,
        "overrides": [],
    }], None, None)

    rows = CodeGraphStore(driver).find_type_relations(
        "repo", "snap", "run-1", "Service", 5
    )

    assert rows[0]["relation"] == "EXTENDS"
    query = driver.execute_query.call_args.args[0]
    assert "overriding.owner_full_name = symbol.name" in query
    assert "(overriding:CodeSymbol)" in query
    assert "-[:OVERRIDES]->(overridden:CodeSymbol)" in query
    arguments = driver.execute_query.call_args.kwargs
    assert arguments["index_run_id"] == "run-1"
    assert arguments["name"] == "Service"


def test_find_dispatch_targets_is_bound_and_groups_implementations():
    driver = MagicMock()
    driver.execute_query.return_value = ([{
        "base_method": "demo.Greeter.greet()",
        "candidate_kind": "dispatch_candidates",
        "implementations": ["demo.AService.greet()", "demo.BService.greet()"],
    }], None, None)

    rows = CodeGraphStore(driver).find_dispatch_targets(
        "repo", "snap", "run-1", "greet", 5
    )

    assert rows[0]["candidate_kind"] == "dispatch_candidates"
    assert len(rows[0]["implementations"]) == 2
    arguments = driver.execute_query.call_args.kwargs
    assert arguments["index_run_id"] == "run-1"
    assert arguments["name"] == "greet"
    assert "OVERRIDES" in driver.execute_query.call_args.args[0]


def test_dispatch_targets_filter_by_receiver_type():
    driver = MagicMock()
    driver.execute_query.side_effect = [
        ([{"matched": ["demo.Greeter"]}], None, None),
        ([{"ancestors": []}], None, None),
        ([{"base_method": "demo.Greeter.greet()",
           "candidate_kind": "dispatch_candidates",
           "implementations": ["demo.AService.greet()"]}], None, None),
    ]

    rows = CodeGraphStore(driver).find_dispatch_targets(
        "repo", "snap", "run-1", "greet", 5, receiver_type="Greeter"
    )

    assert rows[0]["candidate_kind"] == "dispatch_candidates"
    third_call = driver.execute_query.call_args_list[2]
    assert third_call.kwargs["candidate_types"] == ["demo.Greeter"]


def test_dispatch_targets_return_empty_when_receiver_type_unresolvable():
    driver = MagicMock()
    driver.execute_query.side_effect = [
        ([{"matched": ["first.Base", "second.Base"]}], None, None),
    ]

    rows = CodeGraphStore(driver).find_dispatch_targets(
        "repo", "snap", "run-1", "greet", 5, receiver_type="Base"
    )

    assert rows == []


def test_find_callers_is_bound_and_returns_static_rows():
    driver = MagicMock()
    driver.execute_query.return_value = ([{"caller": "App.OrderController.submit",
                                           "path": "src/OrderController.java", "line": 3}], None, None)

    rows = CodeGraphStore(driver).find_callers("repo", "snap", "run-1", "run", 5)

    assert rows[0]["caller"].endswith("submit")
    assert driver.execute_query.call_args.kwargs["name"] == "run"
    assert "CALLS" in driver.execute_query.call_args.args[0]
    assert "callee.short_name = $name" in driver.execute_query.call_args.args[0]


def test_find_callees_is_bound_and_returns_target_locations():
    driver = MagicMock()
    driver.execute_query.return_value = ([{
        "caller": "App.OrderController.submit",
        "callee": "App.OrderService.run",
        "caller_path": "src/OrderController.java",
        "path": "src/OrderService.java",
        "line": 8,
    }], None, None)

    rows = CodeGraphStore(driver).find_callees("repo", "snap", "run-1", "submit", 5)

    assert rows[0]["callee"].endswith("run")
    arguments = driver.execute_query.call_args.kwargs
    assert arguments["index_run_id"] == "run-1"
    assert arguments["name"] == "submit"
    assert "(caller)-[relation:CALLS]->(callee" in driver.execute_query.call_args.args[0]
