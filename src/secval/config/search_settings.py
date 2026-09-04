"""读取和检查搜索板块配置。"""

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

SUPPORTED_EMBEDDING_MODEL = "Qwen/Qwen3-Embedding-0.6B"
SUPPORTED_EMBEDDING_DIMENSION = 1024
SUPPORTED_EMBEDDING_PROVIDERS = {"local", "api"}
SUPPORTED_RERANKER_PROVIDERS = {"none", "local", "api"}


@dataclass
class ServiceAddress:
    """一个本地或远程服务的主机和端口。"""

    host: str
    port: int

    def __post_init__(self) -> None:
        if not self.host.strip():
            raise ValueError("服务主机地址不能为空")

        if self.port < 1 or self.port > 65535:
            raise ValueError("服务端口必须在 1 到 65535 之间")


@dataclass
class EmbeddingSettings:
    """本地或远程 API Embedding 配置。"""

    provider: str
    model_name: str
    dimension: int
    device: str
    max_sequence_length: int

    def __post_init__(self) -> None:
        if self.provider not in SUPPORTED_EMBEDDING_PROVIDERS:
            raise ValueError("Embedding provider 只能是 local 或 api")

        if not self.model_name.strip():
            raise ValueError("Embedding 模型名称不能为空")

        if (
            self.provider == "local"
            and self.model_name != SUPPORTED_EMBEDDING_MODEL
        ):
            raise ValueError(
                "当前向量 Collection 只支持模型："
                f"{SUPPORTED_EMBEDDING_MODEL}"
            )

        if self.dimension != SUPPORTED_EMBEDDING_DIMENSION:
            raise ValueError(
                "当前向量 Collection 只支持向量维度："
                f"{SUPPORTED_EMBEDDING_DIMENSION}"
            )

        if not self.device.strip():
            raise ValueError("Embedding 运行设备不能为空")

        if self.max_sequence_length < 1:
            raise ValueError("Embedding 最大输入长度必须大于 0")


@dataclass
class FusionSettings:
    """RRF 合并前的候选召回配置。"""

    candidate_multiplier: int
    max_candidate_count: int

    def __post_init__(self) -> None:
        if self.candidate_multiplier < 1:
            raise ValueError("候选召回倍数必须大于或等于 1")

        if self.max_candidate_count < 1:
            raise ValueError("最大候选数量必须大于或等于 1")


@dataclass
class RerankerSettings:
    """搜索结果精排配置。"""

    provider: str
    model_name: str
    device: str
    candidate_count: int
    max_sequence_length: int
    batch_size: int

    def __post_init__(self) -> None:
        if self.provider not in SUPPORTED_RERANKER_PROVIDERS:
            raise ValueError("Reranker provider只能是none、local或api")
        if self.provider != "none" and not self.model_name.strip():
            raise ValueError("本地Reranker模型名称不能为空")
        if not self.device.strip():
            raise ValueError("Reranker运行设备不能为空")
        if self.candidate_count < 1:
            raise ValueError("Reranker候选数量必须大于0")
        if self.max_sequence_length < 1 or self.batch_size < 1:
            raise ValueError("Reranker最大长度和批次必须大于0")


@dataclass
class SearchSettings:
    """搜索板块启动时需要的全部配置。"""

    open_search: ServiceAddress
    qdrant: ServiceAddress
    embedding: EmbeddingSettings
    fusion: FusionSettings
    reranker: RerankerSettings


def load_search_settings(
    file_path: str = "config/search.yaml",
) -> SearchSettings:
    """从 YAML 文件读取搜索配置并转换成明确的数据类型。"""

    settings_path = Path(file_path)

    if not settings_path.exists():
        raise ValueError(f"搜索配置文件不存在：{file_path}")

    try:
        raw_settings = yaml.safe_load(
            settings_path.read_text(encoding="utf-8")
        )
    except yaml.YAMLError as error:
        raise ValueError(f"搜索配置文件格式错误：{file_path}") from error

    if not isinstance(raw_settings, dict):
        raise ValueError("搜索配置文件最外层必须是配置对象")

    open_search = _read_service_address(raw_settings, "open_search")
    qdrant = _read_service_address(raw_settings, "qdrant")
    embedding_data = _read_section(raw_settings, "embedding")
    fusion_data = _read_section(raw_settings, "fusion")
    reranker_data = raw_settings.get(
        "reranker",
        {
            "provider": "none",
            "model_name": "BAAI/bge-reranker-base",
            "device": "cpu",
            "candidate_count": 10,
            "max_sequence_length": 256,
            "batch_size": 8,
        },
    )
    if not isinstance(reranker_data, dict):
        raise ValueError("搜索配置中的reranker必须是配置对象")

    try:
        provider = str(embedding_data.get("provider", "local"))
        model_name = str(embedding_data["model_name"])
        dimension = int(embedding_data["dimension"])
        device = str(embedding_data["device"])
        max_sequence_length = int(
            embedding_data["max_sequence_length"]
        )
        candidate_multiplier = int(fusion_data["candidate_multiplier"])
        max_candidate_count = int(fusion_data["max_candidate_count"])
        reranker_provider = str(reranker_data["provider"])
        reranker_model_name = str(reranker_data["model_name"])
        reranker_device = str(reranker_data["device"])
        reranker_candidate_count = int(reranker_data["candidate_count"])
        reranker_max_sequence_length = int(
            reranker_data["max_sequence_length"]
        )
        reranker_batch_size = int(reranker_data["batch_size"])
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("搜索配置缺少字段或字段类型错误") from error

    embedding = EmbeddingSettings(
        provider=provider,
        model_name=model_name,
        dimension=dimension,
        device=device,
        max_sequence_length=max_sequence_length,
    )
    fusion = FusionSettings(
        candidate_multiplier=candidate_multiplier,
        max_candidate_count=max_candidate_count,
    )
    reranker = RerankerSettings(
        provider=reranker_provider,
        model_name=reranker_model_name,
        device=reranker_device,
        candidate_count=reranker_candidate_count,
        max_sequence_length=reranker_max_sequence_length,
        batch_size=reranker_batch_size,
    )

    return SearchSettings(
        open_search=open_search,
        qdrant=qdrant,
        embedding=embedding,
        fusion=fusion,
        reranker=reranker,
    )


def _read_service_address(
    raw_settings: dict[str, Any],
    section_name: str,
) -> ServiceAddress:
    """读取一个服务地址配置。"""

    section = _read_section(raw_settings, section_name)

    try:
        return ServiceAddress(
            host=str(section["host"]),
            port=int(section["port"]),
        )
    except (KeyError, TypeError) as error:
        raise ValueError(
            f"搜索配置中的 {section_name} 缺少 host 或 port"
        ) from error


def _read_section(
    raw_settings: dict[str, Any],
    section_name: str,
) -> dict[str, Any]:
    """读取一个必填配置区块。"""

    section = raw_settings.get(section_name)

    if not isinstance(section, dict):
        raise ValueError(f"搜索配置缺少 {section_name} 区块")

    return section
