"""提供搜索板块的 HTTP API。"""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request, Response, status
from pydantic import BaseModel, Field

from secval.hybrid_search.search_models import SearchQuery, SearchResult
from secval.hybrid_search.search_runtime import (
    SearchRuntime,
    create_search_runtime,
)
from secval.shared_types import RepositoryId, SnapshotId


class SearchRequest(BaseModel):
    """Web 客户端提交的混合搜索条件。"""

    text: str = Field(min_length=1)
    repository_ids: list[str] = Field(min_length=1)
    snapshot_ids: list[str] = Field(min_length=1)
    top_k: int = Field(default=10, ge=1, le=100)
    language: str | None = None
    path_prefix: str | None = None
    chunk_type: str | None = None


class SearchResultResponse(BaseModel):
    """返回给 Web 客户端的一条代码搜索结果。"""

    chunk_id: str
    file_id: str
    repository_id: str
    snapshot_id: str
    relative_path: str
    language: str
    chunk_type: str
    content: str
    start_line: int
    end_line: int
    symbol_id: str | None
    symbol_name: str | None
    rank: int
    final_score: float
    keyword_score: float | None
    vector_score: float | None


class SearchResponse(BaseModel):
    """混合搜索接口的完整响应。"""

    result_count: int
    results: list[SearchResultResponse]


class HealthResponse(BaseModel):
    """搜索服务及两个存储的健康状态。"""

    status: str
    open_search: str
    qdrant: str


def create_search_app(
    runtime: SearchRuntime | None = None,
) -> FastAPI:
    """创建 FastAPI 应用；测试可以传入不加载真实模型的 Runtime。"""

    owns_runtime = runtime is None

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        active_runtime = runtime

        if active_runtime is None:
            active_runtime = create_search_runtime()

        app.state.search_runtime = active_runtime
        yield

        if owns_runtime:
            active_runtime.open_search_connection.transport.close()
            active_runtime.qdrant_client.close()

    app = FastAPI(
        title="Secval Search API",
        version="0.1.0",
        lifespan=lifespan,
    )

    @app.get("/api/health", response_model=HealthResponse)
    def health(request: Request, response: Response) -> HealthResponse:
        """检查 OpenSearch 和 Qdrant 是否可以连接。"""

        active_runtime: SearchRuntime = request.app.state.search_runtime
        open_search_status = "unavailable"
        qdrant_status = "unavailable"

        try:
            if active_runtime.open_search_connection.ping():
                open_search_status = "available"
        except Exception:
            open_search_status = "unavailable"

        try:
            active_runtime.qdrant_client.get_collections()
            qdrant_status = "available"
        except Exception:
            qdrant_status = "unavailable"

        service_status = "healthy"

        if (
            open_search_status != "available"
            or qdrant_status != "available"
        ):
            service_status = "unhealthy"
            response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

        return HealthResponse(
            status=service_status,
            open_search=open_search_status,
            qdrant=qdrant_status,
        )

    @app.post("/api/search", response_model=SearchResponse)
    def search(
        search_request: SearchRequest,
        request: Request,
    ) -> SearchResponse:
        """执行 BM25、向量搜索和 RRF 合并。"""

        active_runtime: SearchRuntime = request.app.state.search_runtime

        try:
            query = _create_search_query(search_request)
            results = active_runtime.search_service.search(query)
        except ValueError as error:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(error),
            ) from error

        result_responses = [
            _create_result_response(result) for result in results
        ]
        return SearchResponse(
            result_count=len(result_responses),
            results=result_responses,
        )

    return app


def _create_search_query(search_request: SearchRequest) -> SearchQuery:
    """把 Web 请求转换成核心搜索模型。"""

    return SearchQuery(
        text=search_request.text,
        repository_ids=[
            RepositoryId(value) for value in search_request.repository_ids
        ],
        snapshot_ids=[
            SnapshotId(value) for value in search_request.snapshot_ids
        ],
        top_k=search_request.top_k,
        language=search_request.language,
        path_prefix=search_request.path_prefix,
        chunk_type=search_request.chunk_type,
    )


def _create_result_response(result: SearchResult) -> SearchResultResponse:
    """把核心搜索结果转换成 JSON 响应模型。"""

    chunk = result.chunk
    return SearchResultResponse(
        chunk_id=str(chunk.chunk_id),
        file_id=str(chunk.file_id),
        repository_id=str(chunk.repository_id),
        snapshot_id=str(chunk.snapshot_id),
        relative_path=chunk.relative_path,
        language=chunk.language,
        chunk_type=chunk.chunk_type,
        content=chunk.content,
        start_line=chunk.start_line,
        end_line=chunk.end_line,
        symbol_id=(
            str(chunk.symbol_id) if chunk.symbol_id is not None else None
        ),
        symbol_name=chunk.symbol_name,
        rank=result.rank,
        final_score=result.final_score,
        keyword_score=result.keyword_score,
        vector_score=result.vector_score,
    )


app = create_search_app()
