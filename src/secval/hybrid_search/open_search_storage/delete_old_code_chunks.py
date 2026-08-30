"""新代码块写入成功后，删除上一批代码块。"""

from opensearchpy import OpenSearch

from secval.hybrid_search.open_search_storage.code_index import CODE_INDEX_NAME
from secval.shared_types import RepositoryId, SnapshotId


def delete_old_code_chunks(
    connection: OpenSearch,
    repository_id: RepositoryId,
    snapshot_id: SnapshotId,
    current_index_run_id: str,
) -> int:
    """删除不属于当前索引批次的旧代码块，并返回删除数量。"""

    if not current_index_run_id.strip():
        raise ValueError("当前索引批次 ID 不能为空")

    response = connection.delete_by_query(
        index=CODE_INDEX_NAME,
        body={
            "query": {
                "bool": {
                    "filter": [
                        {"term": {"repository_id": repository_id}},
                        {"term": {"snapshot_id": snapshot_id}},
                    ],
                    "must_not": [
                        {"term": {"index_run_id": current_index_run_id}},
                    ],
                }
            }
        },
        refresh=True,
        conflicts="proceed",
    )

    return int(response["deleted"])
