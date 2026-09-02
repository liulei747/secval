"""通过 OpenAI 兼容的 HTTP API 生成代码和查询向量。"""

import json
import math
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .local_embedding_model import QUERY_INSTRUCTION

DEFAULT_API_BATCH_SIZE = 64
DEFAULT_API_TIMEOUT_SECONDS = 120
MAX_INITIAL_API_BATCH_SIZE = 16


class EmbeddingApiHttpError(ValueError):
    """保留远程 HTTP 状态码，供批量降级策略判断。"""

    def __init__(self, status_code: int, detail: str) -> None:
        super().__init__(f"Embedding API 返回 HTTP {status_code}：{detail}")
        self.status_code = status_code


class ApiEmbeddingModel:
    """调用远程 /embeddings 接口，并严格检查响应数量和维度。"""

    provider_name = "api"

    def __init__(
        self,
        api_url: str,
        api_key: str,
        model_name: str,
        expected_dimension: int,
        batch_size: int = DEFAULT_API_BATCH_SIZE,
        timeout_seconds: int = DEFAULT_API_TIMEOUT_SECONDS,
    ) -> None:
        if not api_url.strip():
            raise ValueError("SECVAL_EMBEDDING_API_URL 不能为空")
        if not api_key.strip():
            raise ValueError("SECVAL_EMBEDDING_API_KEY 不能为空")
        if not model_name.strip():
            raise ValueError("Embedding API 模型名称不能为空")
        if expected_dimension < 1 or batch_size < 1 or timeout_seconds < 1:
            raise ValueError("Embedding API 的维度、批次和超时必须大于 0")

        normalized_url = api_url.rstrip("/")
        if not normalized_url.endswith("/embeddings"):
            normalized_url = f"{normalized_url}/embeddings"
        self.api_url = normalized_url
        self.api_key = api_key
        self.model_name = model_name
        self.expected_dimension = expected_dimension
        # 部分兼容接口虽然接受 input 数组，但大批量会直接返回模型异常。
        self.batch_size = min(batch_size, MAX_INITIAL_API_BATCH_SIZE)
        self.timeout_seconds = timeout_seconds

    def embed_code(self, code_texts: list[str]) -> list[list[float]]:
        if not code_texts:
            return []
        if any(not text.strip() for text in code_texts):
            raise ValueError("代码文本不能为空")

        vectors: list[list[float]] = []
        start = 0
        active_batch_size = self.batch_size
        while start < len(code_texts):
            batch = code_texts[start:start + active_batch_size]
            try:
                batch_vectors = self._request_vectors(batch)
            except EmbeddingApiHttpError as error:
                if error.status_code != 400 or len(batch) == 1:
                    raise
                # 400“模型异常”常由供应端批量上限触发。把批次减半并
                # 重试同一段，成功后后续请求继续使用已验证的小批次。
                active_batch_size = max(1, len(batch) // 2)
                continue
            vectors.extend(batch_vectors)
            start += len(batch)
        return vectors

    def embed_query(self, query_text: str) -> list[float]:
        if not query_text.strip():
            raise ValueError("向量搜索文本不能为空")
        instructed_query = (
            f"Instruct: {QUERY_INSTRUCTION}\nQuery: {query_text.strip()}"
        )
        return self._request_vectors([instructed_query])[0]

    def _request_vectors(self, texts: list[str]) -> list[list[float]]:
        body = json.dumps(
            {"model": self.model_name, "input": texts, "encoding_format": "float"}
        ).encode("utf-8")
        request = Request(
            self.api_url,
            data=body,
            method="POST",
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
        )

        try:
            with urlopen(request, timeout=self.timeout_seconds) as response:
                response_data = json.loads(response.read().decode("utf-8"))
        except HTTPError as error:
            detail = error.read().decode("utf-8", errors="replace")[:1000]
            raise EmbeddingApiHttpError(error.code, detail) from error
        except (URLError, TimeoutError, json.JSONDecodeError) as error:
            raise ValueError(f"Embedding API 请求失败：{error}") from error

        data = response_data.get("data") if isinstance(response_data, dict) else None
        if not isinstance(data, list) or len(data) != len(texts):
            raise ValueError("Embedding API 返回的向量数量与输入数量不一致")

        try:
            ordered = sorted(data, key=lambda item: int(item["index"]))
            vectors = [self._normalize(item["embedding"]) for item in ordered]
        except (KeyError, TypeError, ValueError) as error:
            raise ValueError("Embedding API 响应缺少合法的 index 或 embedding") from error

        for vector in vectors:
            if len(vector) != self.expected_dimension:
                raise ValueError(
                    "Embedding API 向量维度错误："
                    f"期望 {self.expected_dimension}，实际 {len(vector)}"
                )
        return vectors

    @staticmethod
    def _normalize(raw_vector: object) -> list[float]:
        if not isinstance(raw_vector, list):
            raise TypeError("embedding 不是数组")
        vector = [float(value) for value in raw_vector]
        norm = math.sqrt(sum(value * value for value in vector))
        if norm == 0:
            raise ValueError("Embedding API 返回了零向量")
        return [value / norm for value in vector]
