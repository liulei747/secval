"""使用本地CrossEncoder模型对少量候选代码块进行精排。"""

from threading import Lock

from sentence_transformers import CrossEncoder

from secval.interfaces import RerankerError
from secval.models.search import SearchResult


class LocalReranker:
    provider_name = "local"

    def __init__(
        self,
        model_name: str,
        device: str,
        candidate_count: int,
        max_sequence_length: int,
        batch_size: int,
    ) -> None:
        if not model_name.strip():
            raise ValueError("Reranker模型名称不能为空")
        if candidate_count < 1:
            raise ValueError("Reranker候选数量必须大于0")
        if max_sequence_length < 1 or batch_size < 1:
            raise ValueError("Reranker最大长度和批次必须大于0")

        self.model_name = model_name
        self.candidate_count = candidate_count
        self.batch_size = batch_size
        self._inference_lock = Lock()
        self._model = CrossEncoder(
            model_name,
            device=device,
            max_length=max_sequence_length,
        )

    def rerank(
        self,
        query: str,
        candidates: list[SearchResult],
        top_k: int,
    ) -> list[SearchResult]:
        if top_k < 1:
            raise ValueError("Reranker返回数量必须大于0")
        if not candidates:
            return []

        selected = candidates[: self.candidate_count]
        pairs = [
            (query, _create_candidate_text(result))
            for result in selected
        ]
        try:
            # 单个模型串行推理，防止并发请求争抢CPU和临时内存。
            with self._inference_lock:
                scores = self._model.predict(
                    pairs,
                    batch_size=min(self.batch_size, len(pairs)),
                    show_progress_bar=False,
                )
        except Exception as error:
            raise RerankerError(f"本地Reranker推理失败：{error}") from error

        if len(scores) != len(selected):
            raise RerankerError("Reranker分数数量与候选数量不一致")

        ranked = sorted(
            zip(selected, scores, strict=True),
            key=lambda item: (
                -float(item[1]),
                item[0].rank,
                str(item[0].chunk.chunk_id),
            ),
        )
        results: list[SearchResult] = []
        for index, (original, score) in enumerate(ranked[:top_k]):
            reranker_score = float(score)
            results.append(
                SearchResult(
                    chunk=original.chunk,
                    rank=index + 1,
                    final_score=reranker_score,
                    keyword_score=original.keyword_score,
                    vector_score=original.vector_score,
                    rrf_score=original.rrf_score,
                    reranker_score=reranker_score,
                )
            )

        # candidate_count限制CrossEncoder的推理成本，但不能改变top_k的接口语义。
        # 当调用方需要更多结果时，剩余位置继续沿用RRF顺序。
        for original in candidates[self.candidate_count : top_k]:
            results.append(
                SearchResult(
                    chunk=original.chunk,
                    rank=len(results) + 1,
                    final_score=original.final_score,
                    keyword_score=original.keyword_score,
                    vector_score=original.vector_score,
                    rrf_score=original.rrf_score,
                    reranker_score=None,
                )
            )
        return results


def _create_candidate_text(result: SearchResult) -> str:
    """组合结构信息和原始代码，让模型同时看到语义与代码位置。"""

    chunk = result.chunk
    symbol_name = chunk.symbol_name or ""
    return "\n".join(
        [
            f"File: {chunk.relative_path}",
            f"Type: {chunk.chunk_type}",
            f"Symbol: {symbol_name}",
            f"Lines: {chunk.start_line}-{chunk.end_line}",
            "Code:",
            chunk.content,
        ]
    )
