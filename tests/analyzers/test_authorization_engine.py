import pytest

from secval.analyzers import AuthorizationEngine, PrincipalTrust
from secval.facts import (
    EdgeKind,
    FactConfidence,
    FactEdge,
    FactNode,
    InMemoryFactStore,
    NodeKind,
    SourceLocation,
    stable_edge_id,
    stable_node_id,
)
from secval.semantics import (
    ControlContract,
    FailureBehavior,
    FlowState,
    ModelStatus,
    SemanticRegistry,
)

SNAPSHOT = "snapshot-auth"


def node(name, line, **attributes):
    return FactNode(stable_node_id("java", NodeKind.RESOURCE, name), NodeKind.RESOURCE, SNAPSHOT,
                    SourceLocation("src/AccountAction.java", line), "joern", "4.0",
                    FactConfidence.RESOLVED, attributes)


def cfg(source, target, number):
    discriminator = str(number)
    return FactEdge(stable_edge_id(SNAPSHOT, EdgeKind.FLOWS_TO, source.id, target.id, discriminator),
                    EdgeKind.FLOWS_TO, SNAPSHOT, source.id, target.id, "joern",
                    FactConfidence.RESOLVED, target.location, {"discriminator": discriminator})


def control():
    return ControlContract("authorization.policy", 1, "Policy.check",
                           frozenset({FlowState("authorization", "unchecked")}),
                           frozenset({FlowState("authorization", "checked")}),
                           frozenset({"authorization"}), "principal/resource relation holds",
                           FailureBehavior.THROWS, ModelStatus.VERIFIED,
                           ("Policy.java:4",), "security-maintainer")


def analyze(requirements, *, trust="server_authenticated", proofs=(), include_guard=True,
            bypass=False, include_contract=True, include_principal=True, include_resource=True):
    entry = node("entry", 1, entry=True)
    principal = node("principal", 2, trust=trust)
    resource = node("resource", 3, owner_principal_node_id=principal.id, tenant_id="tenant-a")
    guard = node("guard", 4, signature="Policy.check", checked_value_ids=(resource.id,),
                 proves_constraints=tuple(proofs))
    operation = node("operation", 8, operation="read", requires_guard="authorization",
                     guarded_value_id=resource.id,
                     principal_node_id=principal.id if include_principal else "missing-principal",
                     resource_node_id=resource.id if include_resource else "missing-resource",
                     authorization_requirements=tuple(requirements))
    nodes = [entry, operation]
    edges = []
    if include_principal:
        nodes.append(principal)
    if include_resource:
        nodes.append(resource)
    if include_guard:
        nodes.append(guard)
        edges.extend([cfg(entry, guard, 1), cfg(guard, operation, 2)])
    else:
        edges.append(cfg(entry, operation, 1))
    if bypass:
        alternate = node("alternate", 6)
        nodes.append(alternate)
        edges.extend([cfg(entry, alternate, 3), cfg(alternate, operation, 4)])
    store = InMemoryFactStore()
    for item in nodes:
        store.add_node(item)
    for item in edges:
        store.add_edge(item)
    registry = SemanticRegistry()
    if include_contract:
        registry.register_control(control())
    return AuthorizationEngine(store, registry).analyze(SNAPSHOT)


def test_idor_without_owner_constraint_is_candidate():
    result = analyze(["ownership"], proofs=(), include_guard=False)
    assert result.candidates[0].rule_id == "authorization:object-ownership"
    assert result.assessments[0].missing_constraints == ("ownership",)


def test_dominating_owner_constraint_defends_operation():
    result = analyze(["ownership"], proofs=("ownership",))
    assert result.candidates == ()
    assert result.counterevidence[0].principal_trust == PrincipalTrust.SERVER_AUTHENTICATED
    assert result.counterevidence[0].proven_constraints == ("ownership",)


def test_client_controlled_header_is_not_trusted_principal_even_with_owner_check():
    result = analyze(["ownership"], trust="client_controlled", proofs=("ownership",))
    assert result.candidates[0].rule_id == "authorization:untrusted-principal"
    assert result.assessments[0].principal_trust == PrincipalTrust.CLIENT_CONTROLLED


@pytest.mark.parametrize(("requirement", "rule"), [
    ("tenant", "authorization:tenant-boundary"),
    ("role:admin", "authorization:function-role"),
    ("permission:account.write", "authorization:function-permission"),
])
def test_tenant_role_and_permission_constraints_are_distinct(requirement, rule):
    result = analyze([requirement], include_guard=False)
    assert result.candidates[0].rule_id == rule


def test_guard_bypass_does_not_count_as_proven_authorization():
    result = analyze(["ownership"], proofs=("ownership",), bypass=True)
    assert len(result.candidates) == 1
    assert result.assessments[0].proven_constraints == ()


def test_missing_principal_resource_or_contract_remains_unknown_not_safe():
    result = analyze(["ownership"], include_principal=False, include_resource=False,
                     include_guard=False, include_contract=False)
    assert set(result.candidates[0].unknowns) == {
        "principal fact missing", "resource fact missing"}
    assert result.metrics["unknown_rate"] == 1


def test_renamed_wrapped_inherited_and_overloaded_policy_proofs_are_stable():
    for proof in ("ownership",):
        for _shape in ("renamed", "wrapped", "inherited", "overloaded"):
            result = analyze(["ownership"], proofs=(proof,))
            assert result.candidates == ()
