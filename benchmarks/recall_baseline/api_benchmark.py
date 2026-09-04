"""固定已保存的100条候选测试API排序，不重新召回或修改线上配置。"""

import json
import os
import io
from pathlib import Path
from time import perf_counter
from types import SimpleNamespace
from unittest.mock import patch
from urllib.request import urlopen

from secval.infrastructure.reranker.api_reranker import ApiReranker
from secval.interfaces import RerankerError
from secval.models.search import SearchResult


def main():
    directory = Path(__file__).parent
    original = json.loads((directory / "result.json").read_text(encoding="utf-8"))
    query = next(q for q in original["queries"] if q["query"] == "用户登录")
    candidates = [SearchResult(
        chunk=SimpleNamespace(**row), rank=i + 1, final_score=row["rrf_score"],
        rrf_score=row["rrf_score"], keyword_score=row["keyword_score"],
        vector_score=row["vector_score"],
    ) for i, row in enumerate(query["broad"])]
    # 仅运行时复用已有环境配置，不输出配置或远端响应正文。
    model = ApiReranker(os.environ["SECVAL_EMBEDDING_API_URL"],
                        os.environ["SECVAL_EMBEDDING_API_KEY"],
                        "glm-5.3-flash", 100, timeout_seconds=180)
    report = {"query": query["query"], "model": model.model_name,
              "candidate_count": len(candidates), "timeout_seconds": 180}
    start = perf_counter()
    def inspect_response(request, **kwargs):
        body = json.loads(request.data)
        body["max_tokens"] = 8192
        request.data = json.dumps(body).encode("utf-8")
        report["max_tokens"] = 8192
        with urlopen(request, **kwargs) as response:
            raw = response.read()
        try:
            data = json.loads(raw)
            choice = data.get("choices", [{}])[0]
            message = choice.get("message", {})
            content = message.get("content") or ""
            report["diagnostic"] = {
                "finish_reason": choice.get("finish_reason"),
                "content_characters": len(content),
                "reasoning_characters": len(message.get("reasoning_content") or ""),
            }
            try:
                parsed = json.loads(content)
                ranking = parsed.get("ranking")
                report["diagnostic"]["ranking_count"] = (
                    len(ranking) if isinstance(ranking, list) else None)
            except (ValueError, AttributeError):
                report["diagnostic"]["valid_json"] = False
        except (ValueError, TypeError, AttributeError, IndexError):
            report["diagnostic"] = {"valid_response_envelope": False}
        return io.BytesIO(raw)
    try:
        with patch("secval.infrastructure.reranker.api_reranker.urlopen", inspect_response):
            ranked = model.rerank(query["query"], candidates, 100)
        report["results"] = [
            {"rank": r.rank, "symbol": r.chunk.symbol_name,
             "chunk_id": r.chunk.chunk_id,
             "original_rank": next(c.rank for c in candidates
                                   if c.chunk.chunk_id == r.chunk.chunk_id)}
            for r in ranked]
        report["status"] = "success"
    except RerankerError as error:
        report.update(status="failed", error=str(error))
    report["seconds"] = round(perf_counter() - start, 3)
    (directory / "result.api.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False), flush=True)


if __name__ == "__main__":
    main()
