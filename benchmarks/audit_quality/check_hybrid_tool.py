"""用已建立索引的两文件合成仓库检查审计混合搜索；不调用审计大模型。"""

import argparse

from secval.bootstrap.audit_runtime import create_source_snapshot_store
from secval.bootstrap.search_runtime import create_search_runtime
from secval.infrastructure.audit.index_evidence_tools import EvidenceTools


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", required=True)
    parser.add_argument("--snapshot", required=True)
    arguments = parser.parse_args()

    runtime = create_search_runtime()
    tools = EvidenceTools(runtime.open_search_connection, arguments.repository, arguments.snapshot,
                          create_source_snapshot_store(), search_service=runtime.search_service)
    try:
        scope = tools.call("scope_info", {})
        result = tools.call("hybrid_search", {
            "text": "返回订单之前检查当前用户与订单所有者", "top_k": 5,
        })
        if not result["rows"]:
            raise RuntimeError("合成仓库混合搜索没有返回线索")
        first = result["rows"][0]
        evidence = tools.call("read_chunk", {"chunk_id": first["chunk_id"]})
        if not evidence["rows"]:
            raise RuntimeError("混合搜索线索不能在同一固定视图中读取")
        print({
            "repository_id": scope["repository_id"],
            "snapshot_id": scope["snapshot_id"],
            "index_run_id": result["index_run_id"],
            "clue_count": len(result["rows"]),
            "first_path": first["relative_path"],
            "evidence_id": evidence["rows"][0]["evidence_id"],
            "content_printed": False,
        })
    finally:
        tools.close()
        runtime.open_search_connection.transport.close()
        runtime.qdrant_client.close()


if __name__ == "__main__":
    main()
