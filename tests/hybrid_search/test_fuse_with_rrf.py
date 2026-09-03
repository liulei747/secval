import pytest

from secval.infrastructure.fusion import RRF_RANK_CONSTANT, fuse_with_rrf
from secval.models.code import CodeChunk
from secval.models.search import SearchResult
from secval.shared_types import ChunkId, FileId, RepositoryId, SnapshotId


def create_chunk(chunk_id: str) -> CodeChunk:
    """创建 RRF 测试使用的代码块。"""

    return CodeChunk(
        chunk_id=ChunkId(chunk_id),
        file_id=FileId("file-1"),
        repository_id=RepositoryId("repository-1"),
        snapshot_id=SnapshotId("snapshot-1"),
        relative_path=f"src/{chunk_id}.java",
        language="java",
        chunk_type="method",
        content=f"void {chunk_id}() {{}}",
        start_line=1,
        end_line=1,
    )


def create_keyword_result(
    chunk_id: str,
    rank: int,
    score: float,
) -> SearchResult:
    """创建关键词搜索结果。"""

    return SearchResult(
        chunk=create_chunk(chunk_id),
        rank=rank,
        final_score=score,
        keyword_score=score,
    )


def create_vector_result(
    chunk_id: str,
    rank: int,
    score: float,
) -> SearchResult:
    """创建向量搜索结果。"""

    return SearchResult(
        chunk=create_chunk(chunk_id),
        rank=rank,
        final_score=score,
        vector_score=score,
    )


def test_fuse_keyword_and_vector_rankings() -> None:
    keyword_results = [
        create_keyword_result("chunk-a", rank=1, score=12.0),
        create_keyword_result("chunk-b", rank=2, score=8.0),
    ]
    vector_results = [
        create_vector_result("chunk-b", rank=1, score=0.91),
        create_vector_result("chunk-c", rank=2, score=0.82),
    ]

    results = fuse_with_rrf(keyword_results, vector_results, top_k=3)

    assert [result.chunk.chunk_id for result in results] == [
        "chunk-b",
        "chunk-a",
        "chunk-c",
    ]
    assert [result.rank for result in results] == [1, 2, 3]
    assert results[0].keyword_score == 8.0
    assert results[0].vector_score == 0.91
    assert results[0].final_score == pytest.approx(
        1 / (RRF_RANK_CONSTANT + 2)
        + 1 / (RRF_RANK_CONSTANT + 1)
    )
    assert results[1].vector_score is None
    assert results[2].keyword_score is None


def test_apply_top_k_after_fusion() -> None:
    results = fuse_with_rrf(
        keyword_results=[create_keyword_result("chunk-a", 1, 5.0)],
        vector_results=[create_vector_result("chunk-b", 1, 0.8)],
        top_k=1,
    )

    assert len(results) == 1


def test_reject_duplicate_chunk_in_one_ranking() -> None:
    duplicate_results = [
        create_keyword_result("chunk-a", 1, 5.0),
        create_keyword_result("chunk-a", 2, 4.0),
    ]

    with pytest.raises(ValueError, match="关键词搜索结果包含重复代码块"):
        fuse_with_rrf(duplicate_results, [], top_k=10)


def test_allow_both_rankings_to_be_empty() -> None:
    assert fuse_with_rrf([], [], top_k=10) == []
