"""从当前文本索引分页枚举实际存在的仓库与快照组合。"""

from typing import Any

from opensearchpy import OpenSearch

from .code_index import CODE_INDEX_NAME


def list_indexed_repositories(connection: OpenSearch) -> list[dict[str, Any]]:
    """按仓库和快照同时聚合，不把上传目录误当成已建库数据。"""

    scopes: list[dict[str, Any]] = []
    after = None
    while True:
        composite: dict[str, Any] = {
            "size": 100,
            "sources": [
                {"repository_id": {"terms": {"field": "repository_id"}}},
                {"snapshot_id": {"terms": {"field": "snapshot_id"}}},
            ],
        }
        if after is not None:
            composite["after"] = after
        response = connection.search(
            index=CODE_INDEX_NAME,
            body={"size": 0, "aggs": {"scopes": {"composite": composite}}},
        )
        if response.get("timed_out") or response.get("_shards", {}).get("failed", 0):
            raise ValueError("读取仓库列表不完整，请稍后刷新")
        aggregation = response["aggregations"]["scopes"]
        buckets = aggregation["buckets"]
        for bucket in buckets:
            scopes.append({**bucket["key"], "chunk_count": bucket["doc_count"]})
        next_after = aggregation.get("after_key")
        if not buckets or next_after is None:
            break
        if next_after == after:
            raise ValueError("仓库列表分页未前进，请稍后刷新")
        after = next_after
    return sorted(
        scopes,
        key=lambda scope: (
            -scope["chunk_count"], scope["repository_id"], scope["snapshot_id"],
        ),
    )
