from unittest.mock import MagicMock, patch

import numpy as np
import pytest

from secval.hybrid_search.local_embedding import (
    EMBEDDING_DIMENSION,
    LocalEmbeddingModel,
)
from secval.hybrid_search.local_embedding.local_embedding_model import (
    CODE_EMBEDDING_BATCH_SIZE,
)


@patch(
    "secval.hybrid_search.local_embedding.local_embedding_model."
    "SentenceTransformer"
)
def test_embed_code(mock_model_class: MagicMock) -> None:
    model_instance = MagicMock()
    model_instance.encode.return_value = np.zeros(
        (2, EMBEDDING_DIMENSION),
        dtype=float,
    )
    mock_model_class.return_value = model_instance
    embedding_model = LocalEmbeddingModel()

    vectors = embedding_model.embed_code(
        ["void findUser() {}", "void deleteUser() {}"]
    )

    assert len(vectors) == 2
    assert len(vectors[0]) == EMBEDDING_DIMENSION
    model_instance.encode.assert_called_once_with(
        ["void findUser() {}", "void deleteUser() {}"],
        batch_size=CODE_EMBEDDING_BATCH_SIZE,
        normalize_embeddings=True,
        convert_to_numpy=True,
        show_progress_bar=False,
    )


@patch(
    "secval.hybrid_search.local_embedding.local_embedding_model."
    "SentenceTransformer"
)
def test_embed_query_adds_search_instruction(
    mock_model_class: MagicMock,
) -> None:
    model_instance = MagicMock()
    model_instance.encode.return_value = np.zeros(
        (1, EMBEDDING_DIMENSION),
        dtype=float,
    )
    mock_model_class.return_value = model_instance
    embedding_model = LocalEmbeddingModel()

    vector = embedding_model.embed_query("查找用户权限校验")

    encoded_text = model_instance.encode.call_args.args[0][0]
    assert encoded_text.startswith("Instruct:")
    assert encoded_text.endswith("Query: 查找用户权限校验")
    assert len(vector) == EMBEDDING_DIMENSION


@patch(
    "secval.hybrid_search.local_embedding.local_embedding_model."
    "SentenceTransformer"
)
def test_reject_wrong_vector_dimension(
    mock_model_class: MagicMock,
) -> None:
    model_instance = MagicMock()
    model_instance.encode.return_value = np.zeros((1, 10), dtype=float)
    mock_model_class.return_value = model_instance
    embedding_model = LocalEmbeddingModel()

    with pytest.raises(ValueError, match="Embedding 向量维度错误"):
        embedding_model.embed_code(["void findUser() {}"])
