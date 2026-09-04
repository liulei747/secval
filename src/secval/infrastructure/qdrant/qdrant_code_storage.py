"""使用 Qdrant 保存代码向量。"""

import os
from uuid import NAMESPACE_URL, uuid5

from qdrant_client import QdrantClient
from qdrant_client.http import models

from secval.infrastructure.embedding import EMBEDDING_DIMENSION
from secval.models.code import (
    CodeChunk,
    require_unique_chunk_ids,
)
from secval.models.identifiers import ChunkId, RepositoryId, SnapshotId

CODE_VECTOR_COLLECTION = os.getenv(
    "SECVAL_VECTOR_COLLECTION",
    "secval-code-vectors-qwen3-06b-v2",
)


def create_qdrant_connection(
    host: str = "127.0.0.1",
    port: int = 6333,
) -> QdrantClient:
    """创建本地 Qdrant REST 连接。"""

    if not host.strip():
        raise ValueError("Qdrant 主机地址不能为空")

    if port < 1 or port > 65535:
        raise ValueError("Qdrant 端口必须在 1 到 65535 之间")

    return QdrantClient(host=host, port=port)


def create_code_vector_collection(client: QdrantClient) -> bool:
    """创建代码向量 Collection，并返回本次是否执行了创建。"""

    if client.collection_exists(CODE_VECTOR_COLLECTION):
        collection = _check_existing_collection(client)
        existing_fields = set(getattr(collection, "payload_schema", {}))
        _create_missing_payload_indexes(client, existing_fields)
        return False

    client.create_collection(
        collection_name=CODE_VECTOR_COLLECTION,
        vectors_config=models.VectorParams(
            size=EMBEDDING_DIMENSION,
            distance=models.Distance.COSINE,
        ),
    )
    _create_missing_payload_indexes(client, set())
    return True


def create_vector_point_id(chunk_id: ChunkId) -> str:
    """根据 ChunkId 稳定生成 Qdrant 接受的 UUID。"""

    if not chunk_id.strip():
        raise ValueError("代码块 ID 不能为空")

    point_id = uuid5(NAMESPACE_URL, f"secval-code-chunk:{chunk_id}")
    return str(point_id)


def save_code_vectors(
    client: QdrantClient,
    code_chunks: list[CodeChunk],
    vectors: list[list[float]],
    index_run_id: str,
) -> int:
    """分批保存代码向量，并返回成功提交的向量数量。"""

    if not index_run_id.strip():
        raise ValueError("索引批次 ID 不能为空")

    if len(code_chunks) != len(vectors):
        raise ValueError("代码块数量和向量数量不一致")

    for vector in vectors:
        if len(vector) != EMBEDDING_DIMENSION:
            raise ValueError(
                "Qdrant 向量维度错误："
                f"期望 {EMBEDDING_DIMENSION}，实际 {len(vector)}"
            )

    if len(code_chunks) == 0:
        return 0

    require_unique_chunk_ids(code_chunks)

    points: list[models.PointStruct] = []

    for index in range(len(code_chunks)):
        code_chunk = code_chunks[index]
        vector = vectors[index]
        point = models.PointStruct(
            id=create_vector_point_id(code_chunk.chunk_id),
            vector=vector,
            payload={
                "chunk_id": code_chunk.chunk_id,
                "file_id": code_chunk.file_id,
                "repository_id": code_chunk.repository_id,
                "snapshot_id": code_chunk.snapshot_id,
                "relative_path": code_chunk.relative_path,
                "language": code_chunk.language,
                "chunk_type": code_chunk.chunk_type,
                "index_run_id": index_run_id,
            },
        )
        points.append(point)

    client.upload_points(
        collection_name=CODE_VECTOR_COLLECTION,
        points=points,
        batch_size=64,
        max_retries=3,
        wait=True,
    )
    return len(points)


def delete_old_code_vectors(
    client: QdrantClient,
    repository_id: RepositoryId,
    snapshot_id: SnapshotId,
    current_index_run_id: str,
) -> None:
    """新向量写入成功后，删除不属于当前批次的旧向量。"""

    if not current_index_run_id.strip():
        raise ValueError("当前索引批次 ID 不能为空")

    old_vectors_filter = models.Filter(
        must=[
            models.FieldCondition(
                key="repository_id",
                match=models.MatchValue(value=repository_id),
            ),
            models.FieldCondition(
                key="snapshot_id",
                match=models.MatchValue(value=snapshot_id),
            ),
        ],
        must_not=[
            models.FieldCondition(
                key="index_run_id",
                match=models.MatchValue(value=current_index_run_id),
            )
        ],
    )
    client.delete(
        collection_name=CODE_VECTOR_COLLECTION,
        points_selector=old_vectors_filter,
        wait=True,
    )


def delete_code_vectors_by_run(
    client: QdrantClient,
    index_run_id: str,
) -> None:
    """删除指定未完成批次的向量，用于写入失败后的回滚。"""

    if not index_run_id.strip():
        raise ValueError("索引批次 ID 不能为空")

    client.delete(
        collection_name=CODE_VECTOR_COLLECTION,
        points_selector=models.Filter(
            must=[
                models.FieldCondition(
                    key="index_run_id",
                    match=models.MatchValue(value=index_run_id),
                )
            ]
        ),
        wait=True,
    )


def _check_existing_collection(client: QdrantClient) -> object:
    """拒绝使用维度或距离不符合当前模型的旧 Collection。"""

    collection = client.get_collection(CODE_VECTOR_COLLECTION)
    vectors_config = collection.config.params.vectors
    actual_size = getattr(vectors_config, "size", None)
    actual_distance = getattr(vectors_config, "distance", None)

    if actual_size != EMBEDDING_DIMENSION:
        raise ValueError(
            "Qdrant Collection 向量维度不一致："
            f"期望 {EMBEDDING_DIMENSION}，实际 {actual_size}"
        )

    if actual_distance != models.Distance.COSINE:
        raise ValueError("Qdrant Collection 必须使用余弦距离")

    return collection


def _create_missing_payload_indexes(
    client: QdrantClient,
    existing_fields: set[str],
) -> None:
    """为经常使用的过滤字段补齐索引。"""

    keyword_fields = [
        "repository_id",
        "snapshot_id",
        "language",
        "chunk_type",
        "index_run_id",
    ]

    for field_name in keyword_fields:
        if field_name in existing_fields:
            continue

        client.create_payload_index(
            collection_name=CODE_VECTOR_COLLECTION,
            field_name=field_name,
            field_schema=models.PayloadSchemaType.KEYWORD,
            wait=True,
        )

    if "relative_path" not in existing_fields:
        client.create_payload_index(
            collection_name=CODE_VECTOR_COLLECTION,
            field_name="relative_path",
            field_schema=models.KeywordIndexParams(
                type=models.KeywordIndexType.KEYWORD,
                prefix=True,
            ),
            wait=True,
        )
