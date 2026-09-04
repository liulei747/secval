"""与HTTP框架无关的审计任务输入及业务异常。"""

from dataclasses import dataclass, field

from secval.models.audit_scope import validate_config_paths, validate_scope_paths


class AuditBusyError(ValueError):
    pass


class AuditUnavailableError(ValueError):
    pass


@dataclass(frozen=True)
class AuditTaskInput:
    objective: str
    repository_id: str
    snapshot_id: str
    max_steps: int = 12
    allow_remote_code: bool = False
    security_context: str = ""
    supplied_threat_model: str = ""
    scope_paths: list[str] = field(default_factory=list)
    independent_baseline: bool = True
    approved_config_paths: list[str] = field(default_factory=list)
    allow_remote_config: bool = False
    max_seconds: int = 300

    def __post_init__(self):
        validate_scope_paths(self.scope_paths)
        validate_config_paths(self.approved_config_paths, self.scope_paths)
        if type(self.allow_remote_config) is not bool or (self.approved_config_paths and not self.allow_remote_config):
            raise ValueError("配置可能包含凭据；选择配置文件前必须单独确认允许其正文外发")
        if type(self.independent_baseline) is not bool:
            raise ValueError("independent_baseline必须为布尔值")
        for value in (self.security_context, self.supplied_threat_model):
            if not isinstance(value, str) or len(value) > 12000:
                raise ValueError("安全上下文和已有威胁模型各限12000字符文本")
        if not 5 <= len(self.objective.strip()) <= 4000:
            raise ValueError("调查目标必须为5到4000字符")
        if any(
            not 1 <= len(value.strip()) <= 200
            for value in (self.repository_id, self.snapshot_id)
        ):
            raise ValueError("仓库和快照不能为空或超过200字符")
        if type(self.max_steps) is not int or not 1 <= self.max_steps <= 300:
            raise ValueError("任务调用次数必须为1到300")
        if type(self.max_seconds) is not int or not 30 <= self.max_seconds <= 3600:
            raise ValueError("任务时长预算必须为30到3600秒")
        if self.allow_remote_code is not True:
            raise ValueError("需要确认允许把任务和候选源码发送到审计模型API")
