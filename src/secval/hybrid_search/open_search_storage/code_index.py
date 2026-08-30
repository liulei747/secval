"""定义并创建用于保存代码块的 OpenSearch 索引。"""

from opensearchpy import OpenSearch


CODE_INDEX_NAME = "secval-code-chunks-v3"


CODE_INDEX_BODY = {
    "settings": {
        # 当前是单机开发环境，一个分片已经足够。
        "number_of_shards": 1,
        # 单节点无法保存副本，所以开发环境将副本数设为零。
        "number_of_replicas": 0,
    },
    "mappings": {
        # 拒绝未定义字段，尽早发现字段名拼写错误。
        "dynamic": "strict",
        "properties": {
            "chunk_id": {"type": "keyword"},
            "file_id": {"type": "keyword"},
            "repository_id": {"type": "keyword"},
            "snapshot_id": {"type": "keyword"},
            # 标记代码块属于哪一次索引，用于安全清理上一批数据。
            "index_run_id": {"type": "keyword"},
            "relative_path": {"type": "keyword"},
            "language": {"type": "keyword"},
            "chunk_type": {"type": "keyword"},
            "content": {"type": "text"},
            # 保存经过代码分词器处理的文本，让 user 可以匹配 findUser。
            "search_text": {
                "type": "text",
                "analyzer": "whitespace",
            },
            "start_line": {"type": "integer"},
            "end_line": {"type": "integer"},
            "symbol_id": {"type": "keyword"},
            "symbol_name": {
                "type": "text",
                "fields": {
                    "exact": {"type": "keyword"},
                },
            },
        },
    },
}


def create_code_index(connection: OpenSearch) -> bool:
    """在索引不存在时创建索引，并说明本次是否真的执行了创建。

    返回 True 表示本次新建了索引。
    返回 False 表示索引原本已经存在，没有重复创建。
    """

    if connection.indices.exists(index=CODE_INDEX_NAME):
        return False

    connection.indices.create(
        index=CODE_INDEX_NAME,
        body=CODE_INDEX_BODY,
    )
    return True
