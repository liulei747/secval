"""使用 OpenSearch BM25 搜索代码块。"""

from typing import Any

from opensearchpy import OpenSearch

from secval.hybrid_search.code_tokenizing.tokenize_code import tokenize_code
from secval.hybrid_search.open_search_storage import CODE_INDEX_NAME
from secval.hybrid_search.open_search_storage.load_code_chunk import (
    document_to_code_chunk,
)
from secval.hybrid_search.search_models import SearchQuery, SearchResult


def search_by_keywords(
    connection: OpenSearch,
    query: SearchQuery,
) -> list[SearchResult]:
    """执行 BM25 关键词搜索并返回已经按分数排序的结果。"""

    search_body = build_keyword_search_body(query)
    response = connection.search(
        index=CODE_INDEX_NAME,
        body=search_body,
    )

    results: list[SearchResult] = []
    hits = response["hits"]["hits"]

    for result_index, hit in enumerate(hits):
        rank = result_index + 1
        score = float(hit["_score"])
        code_chunk = document_to_code_chunk(hit["_source"])

        result = SearchResult(
            chunk=code_chunk,
            rank=rank,
            final_score=score,
            keyword_score=score,
        )
        results.append(result)

    return results


def build_keyword_search_body(query: SearchQuery) -> dict[str, Any]:
    """把 SearchQuery 转换成 OpenSearch 查询结构。"""

    # 这里只判断是否含有可搜索内容；实际拆词全部交给 OpenSearch analyzer。
    if len(tokenize_code(query.text)) == 0:
        raise ValueError("搜索文本不包含可以搜索的文字或数字")

    filters: list[dict[str, Any]] = [
        {"terms": {"repository_id": list(query.repository_ids)}},
        {"terms": {"snapshot_id": list(query.snapshot_ids)}},
    ]

    if query.language is not None:
        filters.append({"term": {"language": query.language}})

    if query.path_prefix is not None:
        filters.append({"prefix": {"relative_path": query.path_prefix}})

    if query.chunk_type is not None:
        filters.append({"term": {"chunk_type": query.chunk_type}})

    return {
        "size": query.top_k,
        "query": {
            "bool": {
                "must": {
                    "bool": {
                        "should": [
                            {
                                "multi_match": {
                                    "query": query.text,
                                    "fields": [
                                        "symbol_name^2",
                                        "search_text",
                                    ],
                                    "analyzer": "code_analyzer",
                                }
                            },
                            {
                                "match": {
                                    "content": {
                                        "query": query.text,
                                        "minimum_should_match": "60%",
                                    }
                                }
                            },
                        ],
                        "minimum_should_match": 1,
                    }
                },
                "filter": filters,
            }
        },
    }
