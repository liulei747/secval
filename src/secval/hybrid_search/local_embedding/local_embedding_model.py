"""封装本地 Qwen Embedding 模型。"""

from sentence_transformers import SentenceTransformer

from secval.shared_config.search_settings import (
    SUPPORTED_EMBEDDING_DIMENSION,
    SUPPORTED_EMBEDDING_MODEL,
)

EMBEDDING_MODEL_NAME = SUPPORTED_EMBEDDING_MODEL
EMBEDDING_DIMENSION = SUPPORTED_EMBEDDING_DIMENSION
MAX_SEQUENCE_LENGTH = 512
# 显式限制模型批次，兼顾 CPU 处理速度和内存占用。
# 完整代码仍保存在 OpenSearch；这里只限制用于语义搜索的模型输入。
CODE_EMBEDDING_BATCH_SIZE = 16

QUERY_INSTRUCTION = (
    "Given a code search query, retrieve the source code that best answers it."
)


class LocalEmbeddingModel:
    """加载一次本地模型，并重复生成代码和查询向量。"""

    provider_name = "local"

    def __init__(
        self,
        device: str = "cpu",
        model_name: str = EMBEDDING_MODEL_NAME,
        max_sequence_length: int = MAX_SEQUENCE_LENGTH,
        expected_dimension: int = EMBEDDING_DIMENSION,
    ) -> None:
        """加载模型；首次运行会从 Hugging Face 下载模型文件。"""

        self.model = SentenceTransformer(
            model_name,
            device=device,
        )
        self.model.max_seq_length = max_sequence_length
        self.model_name = model_name
        self.expected_dimension = expected_dimension

    def embed_code(self, code_texts: list[str]) -> list[list[float]]:
        """批量把代码文本转换成归一化向量。"""

        if len(code_texts) == 0:
            return []

        for code_text in code_texts:
            if not code_text.strip():
                raise ValueError("代码文本不能为空")

        vectors = self.model.encode(
            code_texts,
            batch_size=CODE_EMBEDDING_BATCH_SIZE,
            normalize_embeddings=True,
            convert_to_numpy=True,
            show_progress_bar=False,
        ).tolist()

        self._check_vector_dimensions(vectors)
        return vectors

    def embed_query(self, query_text: str) -> list[float]:
        """把一个搜索问题转换成带代码检索指令的归一化向量。"""

        if not query_text.strip():
            raise ValueError("向量搜索文本不能为空")

        instructed_query = (
            f"Instruct: {QUERY_INSTRUCTION}\n"
            f"Query: {query_text.strip()}"
        )
        vectors = self.model.encode(
            [instructed_query],
            normalize_embeddings=True,
            convert_to_numpy=True,
            show_progress_bar=False,
        ).tolist()

        self._check_vector_dimensions(vectors)
        return vectors[0]

    def _check_vector_dimensions(self, vectors: list[list[float]]) -> None:
        """确认模型输出维度与 Qdrant Collection 配置一致。"""

        for vector in vectors:
            if len(vector) != self.expected_dimension:
                raise ValueError(
                    "Embedding 向量维度错误："
                    f"期望 {self.expected_dimension}，实际 {len(vector)}"
                )
