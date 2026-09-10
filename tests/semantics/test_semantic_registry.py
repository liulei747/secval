import pytest

from secval.semantics import (
    BusinessInvariant,
    ControlContract,
    FailureBehavior,
    FlowState,
    FrameworkModel,
    FrameworkModelPack,
    InvariantStatus,
    ModelKind,
    ModelStatus,
    ScopeKind,
    SemanticRegistry,
)

ALL_TESTS = frozenset({"positive", "negative", "wrapper", "inheritance", "overload", "version"})


def model(model_id="spring.request-param", **changes):
    values = {"id": model_id, "revision": 1, "language": "java", "framework": "spring",
              "version_range": ">=6.0,<7.0", "kind": ModelKind.SOURCE,
              "signature": "org.springframework.web.bind.annotation.RequestParam#value()",
              "status": ModelStatus.VERIFIED, "scope": ScopeKind.FRAMEWORK,
              "test_coverage": ALL_TESTS, "evidence_refs": ("spring-docs:request-param",),
              "approved_by": "security-maintainer"}
    values.update(changes)
    return FrameworkModel(**values)


def test_verified_framework_model_requires_every_gate_case():
    for missing in ALL_TESTS:
        with pytest.raises(ValueError, match="缺少完整"):
            model(test_coverage=ALL_TESTS - {missing})


def test_framework_pack_schema_rejects_mixed_versions_and_registers_atomically():
    valid = model()
    pack = FrameworkModelPack("spring.web", 1, "java", "spring", ">=6.0,<7.0", (valid,))
    registry = SemanticRegistry()
    registry.register_pack(pack)
    assert registry.models == [valid]
    with pytest.raises(ValueError, match="不一致"):
        FrameworkModelPack("spring.mixed", 1, "java", "spring", ">=5.0,<6.0", (valid,))


def test_llm_cannot_enable_framework_model_or_invariant():
    with pytest.raises(ValueError, match="LLM提议"):
        model(proposed_by="llm")
    with pytest.raises(ValueError, match="LLM提议"):
        BusinessInvariant("order.owner", 1, "principal", "order", "read",
                          "principal.id == order.ownerId", InvariantStatus.VERIFIED,
                          ("requirements:orders",), "llm", "maintainer")


def test_source_effect_propagator_sanitizer_validator_and_auth_context_are_typed():
    assert {kind.value for kind in ModelKind} >= {
        "source", "effect", "propagator", "sanitizer", "validator", "auth_context"}
    source = model(parameter_positions=(0,), taint_kinds=frozenset({"resource_identity"}))
    assert source.parameter_positions == (0,)


def test_project_extension_wins_without_modifying_framework_model():
    registry = SemanticRegistry()
    framework = model()
    project = model("project.request-param", scope=ScopeKind.PROJECT, project_id="orders")
    registry.register_model(framework)
    registry.register_model(project)
    selected = registry.resolve_models("java", "spring", "6.2", project_id="orders")
    assert selected == (project,)
    assert registry.resolve_models("java", "spring", "6.2", project_id="other") == (framework,)


def test_version_range_excludes_incompatible_framework_versions():
    registry = SemanticRegistry([model()])
    assert registry.resolve_models("java", "spring", "6.1")
    assert registry.resolve_models("java", "spring", "5.3") == ()
    assert registry.resolve_models("java", "spring", "7.0") == ()


def test_equal_scope_revision_and_signature_conflict_is_rejected():
    registry = SemanticRegistry()
    registry.register_model(model())
    with pytest.raises(ValueError, match="语义模型冲突"):
        registry.register_model(model("different-id", taint_kinds=frozenset({"secret"})))


def test_control_contract_records_flow_state_acceptance_and_failure():
    control = ControlContract(
        "path.root-bound", 1, "com.example.PathPolicy#requireInside(Path)",
        frozenset({FlowState("path", "normalized")}),
        frozenset({FlowState("path", "root_bounded")}), frozenset({"path"}),
        "resolved.startsWith(root)", FailureBehavior.THROWS, ModelStatus.VERIFIED,
        ("source:PathPolicy.java:12",), "security-maintainer",
    )
    registry = SemanticRegistry()
    registry.register_control(control)
    assert registry.controls == [control]


def test_invariant_lifecycle_is_revisioned_and_conflicts_are_rejected():
    proposed = BusinessInvariant("refund.limit", 1, "principal", "payment", "refund",
                                 "refund.total <= payment.amount")
    verified = BusinessInvariant("refund.limit", 2, "principal", "payment", "refund",
                                 "refund.total <= payment.amount", InvariantStatus.VERIFIED,
                                 ("requirements:refund",), "human", "product-owner")
    registry = SemanticRegistry()
    registry.register_invariant(proposed)
    registry.register_invariant(verified)
    assert [row.status for row in registry.invariants] == [
        InvariantStatus.PROPOSED, InvariantStatus.VERIFIED]
    with pytest.raises(ValueError, match="修订冲突"):
        registry.register_invariant(BusinessInvariant(
            "refund.limit", 2, "principal", "payment", "refund", "refund.total < 0"))
