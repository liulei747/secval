"""使用 RRF 合并两路搜索排名。"""

from dataclasses import dataclass

from secval.code_processing.code_models import CodeChunk
from secval.hybrid_search.search_models import SearchResult


RRF_RANK_CONSTANT = 60


@dataclass
class _RrfEntry:
    """暂存一个代码块在两路搜索中的分数。"""

    chunk: CodeChunk
    rrf_score: float = 0.0
    keyword_score: float | None = None
    vector_score: float | None = None


def fuse_with_rrf(
    keyword_results: list[SearchResult],
    vector_results: list[SearchResult],
    top_k: int,
) -> list[SearchResult]:
    """按两路结果的排名合并，并返回新的 Top K 结果。"""

    if top_k < 1:
        raise ValueError("RRF 返回数量必须大于或等于 1")

    entries: dict[str, _RrfEntry] = {}
    _add_keyword_results(entries, keyword_results)
    _add_vector_results(entries, vector_results)

    sorted_entries = sorted(
        entries.values(),
        key=lambda entry: (
            -entry.rrf_score,
            str(entry.chunk.chunk_id),
        ),
    )
    selected_entries = sorted_entries[:top_k]
    fused_results: list[SearchResult] = []

    for result_index in range(len(selected_entries)):
        entry = selected_entries[result_index]
        fused_results.append(
            SearchResult(
                chunk=entry.chunk,
                rank=result_index + 1,
                final_score=entry.rrf_score,
                keyword_score=entry.keyword_score,
                vector_score=entry.vector_score,
            )
        )

    return fused_results


def _add_keyword_results(
    entries: dict[str, _RrfEntry],
    results: list[SearchResult],
) -> None:
    """加入关键词排名和关键词原始分数。"""

    seen_chunk_ids: set[str] = set()

    for result in results:
        chunk_id = str(result.chunk.chunk_id)

        if chunk_id in seen_chunk_ids:
            raise ValueError(f"关键词搜索结果包含重复代码块：{chunk_id}")

        seen_chunk_ids.add(chunk_id)
        entry = entries.get(chunk_id)

        if entry is None:
            entry = _RrfEntry(chunk=result.chunk)
            entries[chunk_id] = entry

        entry.rrf_score += _calculate_rrf_score(result.rank)
        entry.keyword_score = result.keyword_score


def _add_vector_results(
    entries: dict[str, _RrfEntry],
    results: list[SearchResult],
) -> None:
    """加入向量排名和向量原始分数。"""

    seen_chunk_ids: set[str] = set()

    for result in results:
        chunk_id = str(result.chunk.chunk_id)

        if chunk_id in seen_chunk_ids:
            raise ValueError(f"向量搜索结果包含重复代码块：{chunk_id}")

        seen_chunk_ids.add(chunk_id)
        entry = entries.get(chunk_id)

        if entry is None:
            entry = _RrfEntry(chunk=result.chunk)
            entries[chunk_id] = entry

        entry.rrf_score += _calculate_rrf_score(result.rank)
        entry.vector_score = result.vector_score


def _calculate_rrf_score(rank: int) -> float:
    """根据一路搜索中的排名计算 RRF 分数。"""

    return 1.0 / (RRF_RANK_CONSTANT + rank)
