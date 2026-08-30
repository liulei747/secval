"""批量保存多个代码块。"""

from opensearchpy import OpenSearch
from opensearchpy.helpers import bulk

from secval.code_processing.code_models import CodeChunk
from secval.hybrid_search.open_search_storage.code_index import CODE_INDEX_NAME
from secval.hybrid_search.open_search_storage.save_code_chunk import (
    code_chunk_to_document,
)


def save_code_chunks(
    connection: OpenSearch,
    code_chunks: list[CodeChunk],
) -> int:
    """批量写入代码块，并返回成功写入的数量。

    空列表不需要请求 OpenSearch，直接返回零。
    bulk 默认会在写入失败时抛出异常，避免调用方误以为全部成功。
    """

    if len(code_chunks) == 0:
        return 0

    actions = []

    for code_chunk in code_chunks:
        action = {
            "_index": CODE_INDEX_NAME,
            "_id": str(code_chunk.chunk_id),
            "_source": code_chunk_to_document(code_chunk),
        }
        actions.append(action)

    successful_count, _ = bulk(connection, actions)
    return successful_count
