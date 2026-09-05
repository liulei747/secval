"""唯一组装入口：配置、适配器和业务服务在此连接。"""

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from secval.config.audit_settings import load_audit_settings
from secval.infrastructure.audit.api_audit_model import AuditModel
from secval.infrastructure.audit.index_evidence_tools import EvidenceTools
from secval.infrastructure.audit.source_snapshot_store import SourceSnapshotStore
from secval.infrastructure.audit.sqlite_audit_store import AuditStore
from secval.models.audit import AuditUnavailableError
from secval.services.audit_service import AuditService


def create_source_snapshot_store():
    settings = load_audit_settings()
    return SourceSnapshotStore(str(Path(settings.database_path).with_name("sources.sqlite3")))


def create_audit_service(connection, search_service=None, graph_store=None, joern_client=None):
    settings = load_audit_settings()

    def model_factory():
        try:
            return AuditModel(settings.api_url, settings.api_key, settings.model_name,
                              timeout_seconds=settings.timeout_seconds,
                              max_output_tokens=settings.max_output_tokens, thinking=settings.thinking,
                              stream=settings.stream)
        except ValueError:
            raise AuditUnavailableError("请配置独立的审计API地址、密钥和模型") from None

    store = AuditStore(settings.database_path)
    source_store = create_source_snapshot_store()
    return AuditService(
        store,
        ThreadPoolExecutor(max_workers=1),
        model_factory,
        lambda repo, snapshot: EvidenceTools(connection, repo, snapshot, source_store,
                                             search_service=search_service, graph_store=graph_store,
                                             joern_client=joern_client),
    )
