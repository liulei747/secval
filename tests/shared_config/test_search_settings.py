from pathlib import Path

import pytest

from secval.config import load_search_settings


def test_load_default_search_settings() -> None:
    settings = load_search_settings("config/search.yaml")

    assert settings.open_search.host == "127.0.0.1"
    assert settings.open_search.port == 9200
    assert settings.qdrant.port == 6333
    assert settings.embedding.provider == "local"
    assert settings.embedding.model_name == "Qwen/Qwen3-Embedding-0.6B"
    assert settings.embedding.dimension == 1024
    assert settings.embedding.device == "cpu"
    assert settings.fusion.candidate_multiplier == 3
    assert settings.fusion.max_candidate_count == 100
    assert settings.reranker.provider == "none"
    assert settings.reranker.candidate_count == 10


def test_reject_unsupported_embedding_dimension(tmp_path: Path) -> None:
    settings_file = tmp_path / "search.yaml"
    settings_file.write_text(
        """
open_search:
  host: 127.0.0.1
  port: 9200
qdrant:
  host: 127.0.0.1
  port: 6333
embedding:
  model_name: Qwen/Qwen3-Embedding-0.6B
  dimension: 768
  device: cpu
  max_sequence_length: 4096
fusion:
  candidate_multiplier: 3
  max_candidate_count: 100
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="只支持向量维度：1024"):
        load_search_settings(str(settings_file))


def test_reject_missing_configuration_section(tmp_path: Path) -> None:
    settings_file = tmp_path / "search.yaml"
    settings_file.write_text(
        "open_search:\n  host: 127.0.0.1\n  port: 9200\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="缺少 qdrant 区块"):
        load_search_settings(str(settings_file))
