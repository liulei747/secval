"""Schemas and approval rules for framework models, controls, and invariants."""

import re
from dataclasses import dataclass, field
from enum import StrEnum

REQUIRED_MODEL_TESTS = frozenset({
    "positive", "negative", "wrapper", "inheritance", "overload", "version",
})


class ModelKind(StrEnum):
    SOURCE = "source"
    EFFECT = "effect"
    PROPAGATOR = "propagator"
    SANITIZER = "sanitizer"
    VALIDATOR = "validator"
    AUTH_CONTEXT = "auth_context"
    TRANSACTION = "transaction"
    ORM = "orm"


class ModelStatus(StrEnum):
    PROPOSED = "PROPOSED"
    VERIFIED = "VERIFIED"
    REJECTED = "REJECTED"


class InvariantStatus(StrEnum):
    PROPOSED = "PROPOSED"
    VERIFIED = "VERIFIED"
    REJECTED = "REJECTED"


class ScopeKind(StrEnum):
    GENERIC = "generic"
    FRAMEWORK = "framework"
    PROJECT = "project"


class FailureBehavior(StrEnum):
    TERMINATES = "terminates"
    RETURNS_FALSE = "returns_false"
    THROWS = "throws"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class FlowState:
    kind: str
    value: str

    def __post_init__(self):
        if not self.kind or not self.value:
            raise ValueError("flow state的kind和value不能为空")


def _require_identifier(value, name):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_.:/@+-]+", value):
        raise ValueError(f"{name}不合法")


@dataclass(frozen=True, slots=True)
class FrameworkModel:
    id: str
    revision: int
    language: str
    framework: str
    version_range: str
    kind: ModelKind
    signature: str
    status: ModelStatus = ModelStatus.PROPOSED
    scope: ScopeKind = ScopeKind.FRAMEWORK
    project_id: str | None = None
    parameter_positions: tuple[int, ...] = ()
    taint_kinds: frozenset[str] = frozenset()
    test_coverage: frozenset[str] = frozenset()
    evidence_refs: tuple[str, ...] = ()
    proposed_by: str = "human"
    approved_by: str | None = None

    def __post_init__(self):
        _require_identifier(self.id, "model id")
        if self.revision < 1 or not self.language or not self.framework or not self.signature:
            raise ValueError("model版本、语言、框架和完整签名不能为空")
        if self.scope == ScopeKind.PROJECT and not self.project_id:
            raise ValueError("项目模型必须声明project_id")
        if self.scope != ScopeKind.PROJECT and self.project_id is not None:
            raise ValueError("非项目模型不得声明project_id")
        if self.proposed_by == "llm" and self.status != ModelStatus.PROPOSED:
            raise ValueError("LLM提议不能直接启用或拒绝模型")
        if self.status == ModelStatus.VERIFIED:
            if not self.approved_by or self.approved_by == "llm":
                raise ValueError("启用模型必须由非LLM审批者批准")
            if not REQUIRED_MODEL_TESTS <= self.test_coverage:
                raise ValueError("启用模型缺少完整变体和版本测试")
            if not self.evidence_refs:
                raise ValueError("启用模型必须有可复核证据")


@dataclass(frozen=True, slots=True)
class FrameworkModelPack:
    id: str
    revision: int
    language: str
    framework: str
    version_range: str
    models: tuple[FrameworkModel, ...]

    def __post_init__(self):
        _require_identifier(self.id, "model pack id")
        if self.revision < 1 or not self.models:
            raise ValueError("model pack版本和模型不能为空")
        identities = set()
        for model in self.models:
            if (model.language, model.framework, model.version_range) != (
                    self.language, self.framework, self.version_range):
                raise ValueError("model pack与内部模型的语言、框架或版本不一致")
            identity = (model.kind, model.signature, model.scope, model.project_id)
            if identity in identities:
                raise ValueError("model pack包含冲突的模型身份")
            identities.add(identity)


@dataclass(frozen=True, slots=True)
class ControlContract:
    id: str
    revision: int
    signature: str
    input_states: frozenset[FlowState]
    output_states: frozenset[FlowState]
    applicable_taint_kinds: frozenset[str]
    accept_condition: str
    failure_behavior: FailureBehavior
    status: ModelStatus = ModelStatus.PROPOSED
    evidence_refs: tuple[str, ...] = ()
    approved_by: str | None = None

    def __post_init__(self):
        _require_identifier(self.id, "control id")
        if self.revision < 1 or not self.signature or not self.accept_condition:
            raise ValueError("control contract字段不完整")
        if self.status == ModelStatus.VERIFIED and (
                not self.evidence_refs or not self.approved_by or self.approved_by == "llm"):
            raise ValueError("启用控制契约必须有证据和非LLM审批")


@dataclass(frozen=True, slots=True)
class BusinessInvariant:
    id: str
    revision: int
    subject: str
    resource: str
    operation: str
    predicate: str
    status: InvariantStatus = InvariantStatus.PROPOSED
    evidence_refs: tuple[str, ...] = ()
    proposed_by: str = "human"
    approved_by: str | None = None

    def __post_init__(self):
        _require_identifier(self.id, "invariant id")
        if self.revision < 1 or not all((self.subject, self.resource, self.operation, self.predicate)):
            raise ValueError("business invariant字段不完整")
        if self.proposed_by == "llm" and self.status != InvariantStatus.PROPOSED:
            raise ValueError("LLM提议不能直接改变不变量生命周期")
        if self.status == InvariantStatus.VERIFIED and (
                not self.evidence_refs or not self.approved_by or self.approved_by == "llm"):
            raise ValueError("启用不变量必须有证据和非LLM审批")


@dataclass(frozen=True, slots=True)
class ConfigurationPolicy:
    """Approved exact-key policy for activation/exposure/control combinations."""

    id: str
    revision: int
    activation_key: str
    activation_values: frozenset
    exposure_key: str
    exposure_values: frozenset
    control_key: str
    safe_control_values: frozenset
    consumer: str
    resource: str
    status: ModelStatus = ModelStatus.PROPOSED
    evidence_refs: tuple[str, ...] = ()
    approved_by: str | None = None

    def __post_init__(self):
        _require_identifier(self.id, "configuration policy id")
        if self.revision < 1 or not all((self.activation_key, self.activation_values,
                                        self.exposure_key, self.exposure_values,
                                        self.control_key, self.safe_control_values,
                                        self.consumer, self.resource)):
            raise ValueError("configuration policy字段不完整")
        if self.status == ModelStatus.VERIFIED and (
                not self.evidence_refs or not self.approved_by or self.approved_by == "llm"):
            raise ValueError("启用配置策略必须有证据和非LLM审批")


@dataclass(frozen=True, slots=True)
class StructuralPolicy:
    id: str
    revision: int
    signatures: frozenset[str]
    dangerous_values: frozenset
    sensitive_contexts: frozenset[str]
    status: ModelStatus = ModelStatus.PROPOSED
    evidence_refs: tuple[str, ...] = ()
    approved_by: str | None = None

    def __post_init__(self):
        _require_identifier(self.id, "structural policy id")
        if self.revision < 1 or not all((self.signatures, self.dangerous_values,
                                        self.sensitive_contexts)):
            raise ValueError("structural policy字段不完整")
        if self.status == ModelStatus.VERIFIED and (
                not self.evidence_refs or not self.approved_by or self.approved_by == "llm"):
            raise ValueError("启用结构策略必须有证据和非LLM审批")


@dataclass(frozen=True, slots=True)
class DependencyAdvisory:
    id: str
    revision: int
    package: str
    affected_versions: str
    vulnerable_signatures: frozenset[str]
    activation_key: str | None = None
    activation_values: frozenset = frozenset()
    status: ModelStatus = ModelStatus.PROPOSED
    evidence_refs: tuple[str, ...] = ()
    approved_by: str | None = None

    def __post_init__(self):
        _require_identifier(self.id, "dependency advisory id")
        if self.revision < 1 or not self.package or not self.affected_versions:
            raise ValueError("dependency advisory字段不完整")
        _version_matches("0", self.affected_versions)
        if bool(self.activation_key) != bool(self.activation_values):
            raise ValueError("运行时激活键和值必须同时声明")
        if self.status == ModelStatus.VERIFIED and (
                not self.evidence_refs or not self.approved_by or self.approved_by == "llm"):
            raise ValueError("启用依赖公告必须有证据和非LLM审批")

    def affects(self, version):
        return _version_matches(version, self.affected_versions)


@dataclass(frozen=True, slots=True)
class StateTransitionInvariant:
    id: str
    revision: int
    entity: str
    operation: str
    allowed_from: frozenset[str]
    allowed_to: frozenset[str]
    required_conditions: frozenset[str] = frozenset()
    repeatable: bool = False
    required_side_effects: frozenset[str] = frozenset()
    status: InvariantStatus = InvariantStatus.PROPOSED
    evidence_refs: tuple[str, ...] = ()
    proposed_by: str = "human"
    approved_by: str | None = None

    def __post_init__(self):
        _require_identifier(self.id, "state invariant id")
        if self.revision < 1 or not all((self.entity, self.operation, self.allowed_from,
                                        self.allowed_to)):
            raise ValueError("state transition invariant字段不完整")
        if self.proposed_by == "llm" and self.status != InvariantStatus.PROPOSED:
            raise ValueError("LLM提议不能直接启用状态不变量")
        if self.status == InvariantStatus.VERIFIED and (
                not self.evidence_refs or not self.approved_by or self.approved_by == "llm"):
            raise ValueError("启用状态不变量必须有证据和非LLM审批")


@dataclass(frozen=True, slots=True)
class ConcurrencyInvariant:
    id: str
    revision: int
    entity: str
    operation: str
    accepted_controls: frozenset[str]
    accepted_isolation_levels: frozenset[str] = frozenset()
    requires_transaction: bool = True
    status: InvariantStatus = InvariantStatus.PROPOSED
    evidence_refs: tuple[str, ...] = ()
    proposed_by: str = "human"
    approved_by: str | None = None

    def __post_init__(self):
        _require_identifier(self.id, "concurrency invariant id")
        if self.revision < 1 or not all((self.entity, self.operation, self.accepted_controls)):
            raise ValueError("concurrency invariant字段不完整")
        if self.proposed_by == "llm" and self.status != InvariantStatus.PROPOSED:
            raise ValueError("LLM提议不能直接启用并发不变量")
        if self.status == InvariantStatus.VERIFIED and (
                not self.evidence_refs or not self.approved_by or self.approved_by == "llm"):
            raise ValueError("启用并发不变量必须有证据和非LLM审批")


@dataclass(slots=True)
class SemanticRegistry:
    models: list[FrameworkModel] = field(default_factory=list)
    controls: list[ControlContract] = field(default_factory=list)
    invariants: list[BusinessInvariant] = field(default_factory=list)
    configuration_policies: list[ConfigurationPolicy] = field(default_factory=list)
    structural_policies: list[StructuralPolicy] = field(default_factory=list)
    dependency_advisories: list[DependencyAdvisory] = field(default_factory=list)
    state_invariants: list[StateTransitionInvariant] = field(default_factory=list)
    concurrency_invariants: list[ConcurrencyInvariant] = field(default_factory=list)

    def register_model(self, model):
        identity = (model.language, model.framework, model.version_range, model.kind,
                    model.signature, model.scope, model.project_id, model.revision)
        conflict = next((row for row in self.models if (
            row.language, row.framework, row.version_range, row.kind, row.signature,
            row.scope, row.project_id, row.revision) == identity and row != model), None)
        if conflict:
            raise ValueError(f"语义模型冲突: {model.id} 与 {conflict.id}")
        if model not in self.models:
            self.models.append(model)

    def register_pack(self, pack):
        staged = SemanticRegistry(models=list(self.models), controls=list(self.controls),
                                  invariants=list(self.invariants),
                                  configuration_policies=list(self.configuration_policies),
                                  structural_policies=list(self.structural_policies),
                                  dependency_advisories=list(self.dependency_advisories),
                                  state_invariants=list(self.state_invariants),
                                  concurrency_invariants=list(self.concurrency_invariants))
        for model in pack.models:
            staged.register_model(model)
        self.models = staged.models

    def resolve_models(self, language, framework, version, *, project_id=None):
        matches = [row for row in self.models if row.status == ModelStatus.VERIFIED
                   and row.language == language and row.framework in {framework, "*"}
                   and _version_matches(version, row.version_range)
                   and (row.scope != ScopeKind.PROJECT or row.project_id == project_id)]
        rank = {ScopeKind.GENERIC: 0, ScopeKind.FRAMEWORK: 1, ScopeKind.PROJECT: 2}
        matches.sort(key=lambda row: (rank[row.scope], row.revision), reverse=True)
        selected = {}
        for row in matches:
            key = (row.kind, row.signature)
            selected.setdefault(key, row)
        return tuple(selected.values())

    def register_control(self, control):
        self._append_revision(self.controls, control)

    def resolve_controls(self):
        verified = [row for row in self.controls if row.status == ModelStatus.VERIFIED]
        latest = {}
        for row in sorted(verified, key=lambda item: item.revision, reverse=True):
            latest.setdefault(row.signature, row)
        return tuple(latest.values())

    def register_invariant(self, invariant):
        self._append_revision(self.invariants, invariant)

    def register_configuration_policy(self, policy):
        self._append_revision(self.configuration_policies, policy)

    def resolve_configuration_policies(self):
        verified = [row for row in self.configuration_policies
                    if row.status == ModelStatus.VERIFIED]
        latest = {}
        for row in sorted(verified, key=lambda item: item.revision, reverse=True):
            latest.setdefault(row.id, row)
        return tuple(latest.values())

    def register_structural_policy(self, policy):
        self._append_revision(self.structural_policies, policy)

    def resolve_structural_policies(self):
        return self._latest_verified(self.structural_policies)

    def register_dependency_advisory(self, advisory):
        self._append_revision(self.dependency_advisories, advisory)

    def resolve_dependency_advisories(self):
        return self._latest_verified(self.dependency_advisories)

    def register_state_invariant(self, invariant):
        self._append_revision(self.state_invariants, invariant)

    def resolve_state_invariants(self):
        verified = [row for row in self.state_invariants
                    if row.status == InvariantStatus.VERIFIED]
        latest = {}
        for row in sorted(verified, key=lambda item: item.revision, reverse=True):
            latest.setdefault((row.entity, row.operation), row)
        return tuple(latest.values())

    def register_concurrency_invariant(self, invariant):
        self._append_revision(self.concurrency_invariants, invariant)

    def resolve_concurrency_invariants(self):
        verified = [row for row in self.concurrency_invariants
                    if row.status == InvariantStatus.VERIFIED]
        latest = {}
        for row in sorted(verified, key=lambda item: item.revision, reverse=True):
            latest.setdefault((row.entity, row.operation), row)
        return tuple(latest.values())

    @staticmethod
    def _latest_verified(collection):
        latest = {}
        for row in sorted((item for item in collection if item.status == ModelStatus.VERIFIED),
                          key=lambda item: item.revision, reverse=True):
            latest.setdefault(row.id, row)
        return tuple(latest.values())

    @staticmethod
    def _append_revision(collection, item):
        conflict = next((row for row in collection
                         if row.id == item.id and row.revision == item.revision and row != item), None)
        if conflict:
            raise ValueError(f"语义修订冲突: {item.id}@{item.revision}")
        if item not in collection:
            collection.append(item)


def _version_tuple(value):
    if not re.fullmatch(r"\d+(?:\.\d+){0,3}", value or ""):
        raise ValueError(f"框架版本不合法: {value}")
    return tuple(int(part) for part in value.split("."))


def _version_matches(version, expression):
    if expression == "*":
        return True
    current = _version_tuple(version)
    for condition in expression.split(","):
        match = re.fullmatch(r"(>=|<=|>|<|==)?(\d+(?:\.\d+){0,3})", condition.strip())
        if not match:
            raise ValueError(f"版本范围不合法: {expression}")
        operator, raw = match.group(1) or "==", match.group(2)
        expected = _version_tuple(raw)
        if not {"==": current == expected, ">=": current >= expected, "<=": current <= expected,
                ">": current > expected, "<": current < expected}[operator]:
            return False
    return True
