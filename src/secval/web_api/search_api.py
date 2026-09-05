"""提供搜索板块的 HTTP API。"""

import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from threading import Lock

from fastapi import (
    FastAPI,
    File,
    Form,
    HTTPException,
    Request,
    Response,
    UploadFile,
    status,
)
from opensearchpy.exceptions import OpenSearchException
from pydantic import BaseModel, Field

from secval.bootstrap.audit_runtime import (
    create_audit_service,
    create_source_snapshot_store,
)
from secval.bootstrap.search_runtime import (
    SearchRuntime,
    create_search_runtime,
)
from secval.infrastructure.opensearch.repository_catalog import (
    list_indexed_repositories,
)
from secval.infrastructure.qdrant import CODE_VECTOR_COLLECTION
from secval.models.code import CodeRepository, CodeSnapshot
from secval.models.identifiers import RepositoryId, SnapshotId
from secval.models.search import SearchQuery, SearchResult
from secval.services.index_service import index_repository
from secval.services.repository_operation import (
    RepositoryBusyError,
    repository_operation,
)
from secval.services.index_job_service import (
    IndexJobService,
    IndexJobStore,
    IndexProcessBusyError,
)
from secval.web_api.audit_api import router as audit_router
from secval.web_api.repository_upload import (
    UploadRepositoryResponse,
    save_uploaded_repository,
    save_uploaded_zip,
)


class SearchRequest(BaseModel):
    """Web 客户端提交的混合搜索条件。"""

    text: str = Field(min_length=1)
    repository_ids: list[str] = Field(min_length=1)
    snapshot_ids: list[str] = Field(min_length=1)
    top_k: int = Field(default=10, ge=1, le=100)
    language: str | None = None
    path_prefix: str | None = None
    chunk_type: str | None = None


class IndexedRepositoryResponse(BaseModel):
    repository_id: str
    snapshot_id: str
    chunk_count: int


class RepositoryCatalogResponse(BaseModel):
    repositories: list[IndexedRepositoryResponse]


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
    symbol_ids: list[str]
    symbol_names: list[str]
    rank: int
    final_score: float
    keyword_score: float | None
    vector_score: float | None
    rrf_score: float | None
    reranker_score: float | None


class SearchResponse(BaseModel):
    """混合搜索接口的完整响应。"""

    result_count: int
    results: list[SearchResultResponse]


class IndexRepositoryRequest(BaseModel):
    """导入挂载在 repositories 根目录下的一个代码仓库。"""

    repository_id: str = Field(min_length=1)
    repository_name: str = Field(min_length=1)
    repository_path: str = Field(min_length=1)
    snapshot_id: str = Field(min_length=1)
    version: str = Field(min_length=1)


class FileErrorResponse(BaseModel):
    relative_path: str
    message: str


class IndexRepositoryResponse(BaseModel):
    index_run_id: str
    total_files: int
    successful_files: int
    failed_files: int
    generated_chunks: int
    saved_chunks: int
    saved_vectors: int
    deleted_chunks: int
    errors: list[FileErrorResponse]


class HealthResponse(BaseModel):
    """搜索、关系图和路径分析服务的健康状态。"""

    status: str
    open_search: str
    qdrant: str
    neo4j: str
    joern: str
    embedding_provider: str
    embedding_model: str
    vector_collection: str
    reranker_provider: str
    reranker_model: str | None


class IndexJobResponse(BaseModel):
    id: str
    parent_id: str | None
    status: str
    stage: str
    request: dict
    result: dict | None
    error: str | None
    created_at: str | None
    started_at: str | None
    finished_at: str | None
    failed_stage: str | None
    stage_history: list[dict]
    worker_id: str | None
    heartbeat_at: str | None
    lease_expires_at: str | None
    attempt: int
    lease_state: str
    queue_position: int | None


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
        app.state.index_lock = Lock()
        app.state.source_snapshot_store = create_source_snapshot_store()
        job_database = os.getenv("SECVAL_INDEX_JOB_DB", "data/index_jobs.sqlite3")
        app.state.index_job_service = IndexJobService(
            IndexJobStore(job_database),
            lambda values, progress: _index_result_dict(_execute_index(
                active_runtime, app.state.source_snapshot_store, app.state.index_lock,
                IndexRepositoryRequest(**values), progress,
            )),
        )
        app.state.audit_service = create_audit_service(active_runtime.open_search_connection,
                                                       active_runtime.search_service,
                                                       active_runtime.code_graph_store,
                                                       active_runtime.joern_client)
        yield
        app.state.index_job_service.close()
        app.state.audit_service.close()

        if owns_runtime:
            active_runtime.open_search_connection.transport.close()
            active_runtime.qdrant_client.close()
            if active_runtime.code_graph_store is not None:
                active_runtime.code_graph_store.close()

    app = FastAPI(
        title="Secval Search API",
        version="0.1.0",
        lifespan=lifespan,
    )

    @app.get("/api/health", response_model=HealthResponse)
    def health(request: Request, response: Response) -> HealthResponse:
        """检查搜索、关系图和路径分析服务是否可以连接。"""

        active_runtime: SearchRuntime = request.app.state.search_runtime
        open_search_status = "unavailable"
        qdrant_status = "unavailable"
        neo4j_status = "disabled" if active_runtime.code_graph_store is None else "unavailable"
        joern_status = "disabled" if active_runtime.joern_client is None else "unavailable"

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

        try:
            if active_runtime.code_graph_store is not None:
                active_runtime.code_graph_store.verify()
                neo4j_status = "available"
        except Exception:
            neo4j_status = "unavailable"

        try:
            if active_runtime.joern_client is not None:
                active_runtime.joern_client.verify()
                joern_status = "available"
        except Exception:
            joern_status = "unavailable"

        service_status = "healthy"

        if (
            open_search_status != "available"
            or qdrant_status != "available"
            or neo4j_status == "unavailable"
            or joern_status == "unavailable"
        ):
            service_status = "unhealthy"
            response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

        return HealthResponse(
            status=service_status,
            open_search=open_search_status,
            qdrant=qdrant_status,
            neo4j=neo4j_status,
            joern=joern_status,
            embedding_provider=active_runtime.embedding_model.provider_name,
            embedding_model=active_runtime.embedding_model.model_name,
            vector_collection=CODE_VECTOR_COLLECTION,
            reranker_provider=active_runtime.reranker.provider_name,
            reranker_model=active_runtime.reranker.model_name,
        )

    @app.get("/api/repositories", response_model=RepositoryCatalogResponse)
    def repository_catalog(request: Request) -> RepositoryCatalogResponse:
        """枚举当前文本索引中的仓库/快照，不读取密钥或源代码正文。"""

        active_runtime: SearchRuntime = request.app.state.search_runtime
        try:
            scopes = list_indexed_repositories(active_runtime.open_search_connection)
        except (OpenSearchException, ValueError) as error:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="读取已索引仓库失败，请检查OpenSearch后刷新",
            ) from error
        return RepositoryCatalogResponse(
            repositories=[IndexedRepositoryResponse(**scope) for scope in scopes]
        )

    @app.post("/api/repositories/index-jobs", response_model=IndexJobResponse, status_code=202)
    def create_index_job(index_request: IndexRepositoryRequest, request: Request):
        """立即返回任务编号，避免浏览器长时间保持索引连接。"""
        try:
            return request.app.state.index_job_service.create(index_request.model_dump())
        except ValueError as error:
            raise HTTPException(status_code=409, detail=str(error)) from None

    @app.get("/api/repositories/index-jobs", response_model=list[IndexJobResponse])
    def list_index_jobs(request: Request):
        return request.app.state.index_job_service.list()

    @app.get("/api/repositories/index-jobs/{job_id}", response_model=IndexJobResponse)
    def get_index_job(job_id: str, request: Request):
        try:
            return request.app.state.index_job_service.get(job_id)
        except KeyError:
            raise HTTPException(status_code=404, detail="索引任务不存在") from None

    @app.post("/api/repositories/index-jobs/{job_id}/resume",
              response_model=IndexJobResponse, status_code=202)
    def resume_index_job(job_id: str, request: Request):
        try:
            return request.app.state.index_job_service.resume(job_id)
        except KeyError:
            raise HTTPException(status_code=404, detail="索引任务不存在") from None
        except ValueError as error:
            raise HTTPException(status_code=409, detail=str(error)) from None

    @app.post("/api/repositories/index-jobs/{job_id}/cancel", response_model=IndexJobResponse)
    def cancel_index_job(job_id: str, request: Request):
        """请求任务在提交新索引之前的下一个安全阶段停止。"""
        try:
            return request.app.state.index_job_service.cancel(job_id)
        except KeyError:
            raise HTTPException(status_code=404, detail="索引任务不存在") from None
        except ValueError as error:
            raise HTTPException(status_code=409, detail=str(error)) from None

    @app.post("/api/repositories/index-jobs/{job_id}/recover-stale",
              response_model=IndexJobResponse)
    def recover_stale_index_job(job_id: str, request: Request):
        """确认租约过期且无人持锁后，将任务标记为可显式续跑。"""
        try:
            return request.app.state.index_job_service.recover_stale(job_id)
        except KeyError:
            raise HTTPException(status_code=404, detail="索引任务不存在") from None
        except ValueError as error:
            raise HTTPException(status_code=409, detail=str(error)) from None

    @app.post("/api/search", response_model=SearchResponse)
    def search(
        search_request: SearchRequest,
        request: Request,
    ) -> SearchResponse:
        """执行BM25、向量召回、RRF融合和可选重排序。"""

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

    @app.post(
        "/api/repositories/upload",
        response_model=UploadRepositoryResponse,
        status_code=status.HTTP_201_CREATED,
    )
    def upload_code_repository(
        request: Request,
        repository_directory: str = Form(min_length=1),
        replace_existing: bool = Form(default=False),
        files: list[UploadFile] = File(min_length=1),
    ) -> UploadRepositoryResponse:
        """接收浏览器选择的代码目录，并保存到 repositories 根目录。"""

        try:
            with repository_operation(request.app.state.index_lock):
                result = save_uploaded_repository(
                    repository_directory=repository_directory,
                    uploaded_files=files,
                    replace_existing=replace_existing,
                )
        except (FileExistsError, RepositoryBusyError) as error:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=str(error),
            ) from error
        except (ValueError, OSError) as error:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(error),
            ) from error
        finally:
            for uploaded_file in files:
                uploaded_file.file.close()

        return result

    @app.post(
        "/api/repositories/upload-zip",
        response_model=UploadRepositoryResponse,
        status_code=status.HTTP_201_CREATED,
    )
    def upload_code_repository_zip(
        request: Request,
        repository_directory: str = Form(min_length=1),
        replace_existing: bool = Form(default=False),
        zip_file: UploadFile = File(),
    ) -> UploadRepositoryResponse:
        """接收 ZIP 代码仓库，安全解压后保存到 repositories 根目录。"""

        try:
            with repository_operation(request.app.state.index_lock):
                result = save_uploaded_zip(
                    repository_directory=repository_directory,
                    uploaded_zip=zip_file,
                    replace_existing=replace_existing,
                )
        except (FileExistsError, RepositoryBusyError) as error:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=str(error),
            ) from error
        except (ValueError, OSError) as error:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(error),
            ) from error
        finally:
            zip_file.file.close()

        return result

    @app.post(
        "/api/repositories/index",
        response_model=IndexRepositoryResponse,
    )
    def index_code_repository(
        index_request: IndexRepositoryRequest,
        request: Request,
    ) -> IndexRepositoryResponse:
        """处理一个已挂载仓库，并原子式替换它当前快照的搜索数据。"""

        active_runtime: SearchRuntime = request.app.state.search_runtime

        try:
            result = request.app.state.index_job_service.run_exclusive(
                lambda: _execute_index(
                    active_runtime, request.app.state.source_snapshot_store,
                    request.app.state.index_lock, index_request,
                )
            )
        except (RepositoryBusyError, IndexProcessBusyError) as error:
            raise HTTPException(status_code=409, detail=str(error)) from None
        except (ValueError, OSError) as error:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(error),
            ) from error

        return IndexRepositoryResponse(**_index_result_dict(result))

    app.include_router(audit_router)
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


def _resolve_repository_path(repository_path: str) -> Path:
    """安全解析容器内 repositories 根目录下的相对路径。"""

    relative_path = Path(repository_path.strip())
    if relative_path.is_absolute():
        raise ValueError("仓库路径必须是 repositories 根目录下的相对路径")

    repositories_root = Path(
        os.getenv("SECVAL_REPOSITORIES_ROOT", "/repositories")
    ).resolve()
    resolved_path = (repositories_root / relative_path).resolve()

    if not resolved_path.is_relative_to(repositories_root):
        raise ValueError("仓库路径不能超出 repositories 根目录")

    if not resolved_path.is_dir():
        raise ValueError(f"仓库目录不存在：{repository_path}")

    return resolved_path


def _execute_index(runtime, source_store, index_lock, index_request, progress=None):
    """同步执行一次索引；Web同步接口和后台任务共用同一套规则。"""
    repository_root = _resolve_repository_path(index_request.repository_path)
    repository = CodeRepository(
        repository_id=RepositoryId(index_request.repository_id),
        name=index_request.repository_name,
        root_path=str(repository_root),
    )
    snapshot = CodeSnapshot(
        snapshot_id=SnapshotId(index_request.snapshot_id),
        repository_id=repository.repository_id,
        version=index_request.version,
    )
    with repository_operation(index_lock):
        return index_repository(
            open_search_connection=runtime.open_search_connection,
            qdrant_client=runtime.qdrant_client,
            embedding_model=runtime.embedding_model,
            repository=repository,
            snapshot=snapshot,
            source_store=source_store,
            graph_store=runtime.code_graph_store,
            joern_client=runtime.joern_client,
            progress=progress,
        )


def _index_result_dict(result):
    process_result = result.process_result
    return {
        "index_run_id": result.index_run_id,
        "total_files": process_result.total_files,
        "successful_files": process_result.successful_files,
        "failed_files": len(process_result.errors),
        "generated_chunks": len(process_result.chunks),
        "saved_chunks": result.saved_chunks,
        "saved_vectors": result.saved_vectors,
        "deleted_chunks": result.deleted_chunks,
        "errors": [{"relative_path": error.relative_path, "message": error.message}
                   for error in process_result.errors],
    }


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
        symbol_ids=[str(symbol_id) for symbol_id in chunk.symbol_ids],
        symbol_names=list(chunk.symbol_names),
        rank=result.rank,
        final_score=result.final_score,
        keyword_score=result.keyword_score,
        vector_score=result.vector_score,
        rrf_score=result.rrf_score,
        reranker_score=result.reranker_score,
    )


app = create_search_app()
