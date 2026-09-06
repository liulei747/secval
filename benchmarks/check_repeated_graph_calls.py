"""用临时 Neo4j 批次验证重复和递归调用；结束仅清理本次创建的批次。"""

from uuid import uuid4

from secval.bootstrap.graph_runtime import create_optional_code_graph_store
from secval.models.code import CodeCall, CodeChunk
from secval.models.identifiers import ChunkId, FileId, RepositoryId, SnapshotId, SymbolId


def main():
    store = create_optional_code_graph_store()
    if store is None:
        raise RuntimeError("需要配置本地 Neo4j")
    repository_id = "secval-repeat-check-" + uuid4().hex
    snapshot_id = "demo"
    run_id = "demo-run"
    chunks = []
    for name, line in (("caller", 1), ("target", 8)):
        chunks.append(CodeChunk(
            ChunkId(name), FileId("demo-file"), RepositoryId(repository_id),
            SnapshotId(snapshot_id), "Demo.java", "java", "method",
            "void " + name + "() {}", line, line,
            symbol_id=SymbolId(name), symbol_names=["Demo." + name + "()"],
            code_calls=[CodeCall("target", 3, "Demo", 0),
                        CodeCall("target", 5, "Demo", 0)] if name == "caller" else [],
        ))
    chunks.append(CodeChunk(
        ChunkId("recursive"), FileId("demo-file"), RepositoryId(repository_id),
        SnapshotId(snapshot_id), "Demo.java", "java", "method",
        "void recursive() { this.recursive(); }", 10, 10,
        symbol_id=SymbolId("recursive"), symbol_names=["Demo.recursive()"],
        code_calls=[CodeCall("recursive", 10, "Demo", 0)],
    ))
    try:
        store.save_snapshot(repository_id, snapshot_id, run_id, chunks)
        rows = store.find_callees(repository_id, snapshot_id, run_id, "caller")
        assert sorted(row["call_line"] for row in rows) == [3, 5], rows
        rows = store.find_callers(repository_id, snapshot_id, run_id, "target")
        assert sorted(row["line"] for row in rows) == [3, 5], rows
        for query in (store.find_callers, store.find_callees):
            rows = query(repository_id, snapshot_id, run_id, "recursive")
            assert len(rows) == 1, rows
            assert rows[0]["caller"] == rows[0]["callee"] == "Demo.recursive()"
        print("Neo4j 双向查询通过：重复调用第 3/5 行及递归调用均保留")
    finally:
        # 唯一随机仓库 ID，且只删除该批次的三个节点类型。
        snapshot_key = repository_id + ":" + snapshot_id + ":" + run_id
        store.driver.execute_query(
            "MATCH (n) WHERE (n:CodeSnapshot OR n:CodeFile OR n:CodeSymbol) "
            "AND (n.key = $key OR n.key STARTS WITH $prefix) DETACH DELETE n",
            key=snapshot_key, prefix=snapshot_key + ":", database_="neo4j",
        )
        store.close()


if __name__ == "__main__":
    main()
