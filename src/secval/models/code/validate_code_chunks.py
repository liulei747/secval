"""代码块批次级校验。"""

from collections import Counter

from secval.models.code.code_chunk import CodeChunk


def require_unique_chunk_ids(code_chunks: list[CodeChunk]) -> None:
    """拒绝同一批次中会在 OpenSearch 或 Qdrant 互相覆盖的 ID。"""

    counts = Counter(str(chunk.chunk_id) for chunk in code_chunks)
    duplicate_ids = sorted(
        chunk_id for chunk_id, count in counts.items() if count > 1
    )
    if duplicate_ids:
        preview = ", ".join(duplicate_ids[:3])
        raise ValueError(f"代码块 ID 不能重复：{preview}")
