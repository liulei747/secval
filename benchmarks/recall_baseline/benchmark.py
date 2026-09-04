"""只调用现有搜索 API 获取候选，再离线对照；不读取密钥、不修改索引。"""

import json
from pathlib import Path
from time import perf_counter
from types import SimpleNamespace
from urllib.request import Request, urlopen

from secval.infrastructure.reranker.local_reranker import LocalReranker
from secval.models.search import SearchResult


QUERIES = [
    "用户登录",
    "用户账号密码登录的入口在哪里",
    "文件上传接口在哪里",
    "检查登录账号是否重复",
    "登录日志在哪里记录",
    "FormFilter.executeLogin",
]


def search(query, count):
    payload = dict(text=query, top_k=count,
                   repository_ids=["jeesite-project-api"],
                   snapshot_ids=["jeesite-project-main"])
    request = Request("http://api:8000/api/search",
                      data=json.dumps(payload).encode(),
                      headers={"Content-Type": "application/json"})
    start = perf_counter()
    with urlopen(request, timeout=180) as response:
        rows = json.load(response)["results"]
    return rows, round(perf_counter() - start, 3)


def compact(rows):
    return [dict(symbol=r.chunk.symbol_name, path=r.chunk.relative_path,
                 line=r.chunk.start_line, rrf=r.rrf_score,
                 rerank=r.reranker_score) for r in rows]


def main():
    output = Path(__file__).with_name("result.json")
    report = dict(model="BAAI/bge-reranker-base", device="cpu",
                  max_length=256, batch_size=8, queries=[])
    # 先采集线上结果，避免离线模型推理与线上计时争抢 CPU。
    for query in QUERIES:
        baseline, baseline_seconds = search(query, 5)
        broad, broad_seconds = search(query, 100)
        broad.sort(key=lambda row: (-row["rrf_score"], row["chunk_id"]))
        report["queries"].append(dict(query=query, baseline=baseline,
            baseline_seconds=baseline_seconds, broad=broad,
            broad_api_seconds=broad_seconds, variants={}))
        output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        print(query, "collected", baseline_seconds, broad_seconds, flush=True)
    start = perf_counter()
    reranker = LocalReranker(report["model"], "cpu", 100, 256, 8)
    report["model_load_seconds"] = round(perf_counter() - start, 3)
    for item in report["queries"]:
        candidates = [SearchResult(
            chunk=SimpleNamespace(**row), rank=index + 1,
            final_score=row["rrf_score"], keyword_score=row["keyword_score"],
            vector_score=row["vector_score"], rrf_score=row["rrf_score"])
            for index, row in enumerate(item["broad"])]
        item["rrf_top5"] = compact(candidates[:5])
        for count in (10, 50, 100):
            reranker.candidate_count = count
            start = perf_counter()
            rows = reranker.rerank(item["query"], candidates, top_k=count)
            elapsed = round(perf_counter() - start, 3)
            item["variants"][str(count)] = dict(seconds=elapsed, results=compact(rows))
            print(item["query"], count, elapsed,
                  [r.chunk.symbol_name for r in rows[:5]], flush=True)
        output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
