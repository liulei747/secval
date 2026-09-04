from unittest.mock import MagicMock

from secval.infrastructure.opensearch import (
    CODE_INDEX_NAME,
    build_keyword_search_body,
    search_by_keywords,
)
from secval.models.identifiers import RepositoryId, SnapshotId
from secval.models.search import SearchQuery


def create_search_query() -> SearchQuery:
    """创建测试使用的关键词搜索请求。"""

    return SearchQuery(
        text="findUser",
        repository_ids=[RepositoryId("repository-1")],
        snapshot_ids=[SnapshotId("snapshot-1")],
        top_k=5,
        language="java",
        path_prefix="src/",
        chunk_type="method",
    )


def test_build_keyword_search_body() -> None:
    search_body = build_keyword_search_body(create_search_query())

    lexical_queries = search_body["query"]["bool"]["must"]["bool"]
    multi_match = lexical_queries["should"][0]["multi_match"]
    content_match = lexical_queries["should"][1]["match"]["content"]
    filters = search_body["query"]["bool"]["filter"]

    assert search_body["size"] == 5
    assert multi_match["query"] == "findUser"
    assert multi_match["analyzer"] == "code_analyzer"
    assert multi_match["fields"] == ["symbol_name^2", "search_text"]
    assert lexical_queries["minimum_should_match"] == 1
    assert content_match == {
        "query": "findUser",
        "minimum_should_match": "60%",
    }
    assert {"terms": {"repository_id": ["repository-1"]}} in filters
    assert {"terms": {"snapshot_id": ["snapshot-1"]}} in filters
    assert {"term": {"language": "java"}} in filters
    assert {"prefix": {"relative_path": "src/"}} in filters
    assert {"term": {"chunk_type": "method"}} in filters


def test_convert_open_search_hits_to_search_results() -> None:
    connection = MagicMock()
    connection.search.return_value = {
        "hits": {
            "hits": [
                {
                    "_score": 4.25,
                    "_source": {
                        "chunk_id": "chunk-1",
                        "file_id": "file-1",
                        "repository_id": "repository-1",
                        "snapshot_id": "snapshot-1",
                        "relative_path": "src/UserService.java",
                        "language": "java",
                        "chunk_type": "method",
                        "content": "User findUser() { return user; }",
                        "start_line": 10,
                        "end_line": 12,
                        "symbol_id": "symbol-1",
                        "symbol_name": "findUser",
                    },
                }
            ]
        }
    }

    results = search_by_keywords(connection, create_search_query())

    connection.search.assert_called_once()
    assert connection.search.call_args.kwargs["index"] == CODE_INDEX_NAME
    assert len(results) == 1
    assert results[0].rank == 1
    assert results[0].keyword_score == 4.25
    assert results[0].final_score == 4.25
    assert results[0].chunk.chunk_id == "chunk-1"
    assert results[0].chunk.symbol_name == "findUser"


def test_reject_query_without_searchable_tokens() -> None:
    query = SearchQuery(
        text="...",
        repository_ids=[RepositoryId("repository-1")],
        snapshot_ids=[SnapshotId("snapshot-1")],
    )

    try:
        build_keyword_search_body(query)
        raise AssertionError("应该拒绝没有可搜索内容的查询")
    except ValueError as error:
        assert str(error) == "搜索文本不包含可以搜索的文字或数字"
