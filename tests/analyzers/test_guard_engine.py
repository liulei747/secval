from secval.analyzers import GuardEngine
from secval.candidates import CandidateKind
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

SNAPSHOT = "snapshot-guard"


def node(name, line, **attributes):
    return FactNode(stable_node_id("java", NodeKind.VALUE, name), NodeKind.VALUE, SNAPSHOT,
                    SourceLocation("src/Action.java", line), "joern", "4.0",
                    FactConfidence.RESOLVED, attributes)


def cfg(source, target, number):
    discriminator = str(number)
    return FactEdge(stable_edge_id(SNAPSHOT, EdgeKind.FLOWS_TO, source.id, target.id, discriminator),
                    EdgeKind.FLOWS_TO, SNAPSHOT, source.id, target.id, "joern",
                    FactConfidence.RESOLVED, target.location, {"discriminator": discriminator})


def contract(failure=FailureBehavior.THROWS):
    return ControlContract("auth.require-owner", 1, "Policy.requireOwner",
                           frozenset({FlowState("authorization", "unchecked")}),
                           frozenset({FlowState("authorization", "owner_checked")}),
                           frozenset({"authorization"}), "ownerId == principalId", failure,
                           ModelStatus.VERIFIED, ("Policy.java:4",), "security-maintainer")


def analyze(nodes, edges, controls=(None,)):
    store = InMemoryFactStore()
    for item in nodes:
        store.add_node(item)
    for item in edges:
        store.add_edge(item)
    registry = SemanticRegistry()
    for item in controls:
        if item is not None:
            registry.register_control(item)
    return GuardEngine(store, registry).analyze(SNAPSHOT)


def scenario(*, checked="resource", failure=FailureBehavior.THROWS):
    entry = node("entry", 1, entry=True)
    guard = node("guard", 3, signature="Policy.requireOwner", checked_value_ids=(checked,))
    effect = node("effect", 6, requires_guard="authorization", guarded_value_id="resource")
    return entry, guard, effect, contract(failure)


def test_dominating_same_value_terminating_guard_is_counterevidence():
    entry, guard, effect, control = scenario()
    result = analyze([entry, guard, effect], [cfg(entry, guard, 1), cfg(guard, effect, 2)], [control])
    assert result.candidates == ()
    evidence = result.counterevidence[0]
    assert (evidence.dominates, evidence.same_value, evidence.failure_terminates) == (True, True, True)
    assert not evidence.bypass_paths
    assert evidence.locations == (guard.location, effect.location)


def test_branch_bypass_is_reported_as_structured_candidate():
    entry, guard, effect, control = scenario()
    bypass = node("alternate", 4)
    edges = [cfg(entry, guard, 1), cfg(guard, effect, 2),
             cfg(entry, bypass, 3), cfg(bypass, effect, 4)]
    result = analyze([entry, guard, bypass, effect], edges, [control])
    assert result.candidates[0].kind == CandidateKind.MISSING_GUARD
    assert result.assessments[0].dominates is False
    assert result.assessments[0].bypass_paths


def test_guard_on_different_value_does_not_defend_effect():
    entry, guard, effect, control = scenario(checked="other-resource")
    result = analyze([entry, guard, effect], [cfg(entry, guard, 1), cfg(guard, effect, 2)], [control])
    assert len(result.candidates) == 1
    assert result.assessments[0].same_value is False


def test_nonterminating_failure_does_not_defend_effect():
    entry, guard, effect, control = scenario(failure=FailureBehavior.RETURNS_FALSE)
    result = analyze([entry, guard, effect], [cfg(entry, guard, 1), cfg(guard, effect, 2)], [control])
    assert len(result.candidates) == 1
    assert result.assessments[0].failure_terminates is False


def test_explicit_failure_branch_termination_supports_boolean_validator():
    entry, _guard, effect, control = scenario(failure=FailureBehavior.RETURNS_FALSE)
    guarded = node("guarded", 3, signature="Policy.requireOwner",
                   checked_value_ids=("resource",), failure_terminates=True)
    result = analyze([entry, guarded, effect], [cfg(entry, guarded, 1), cfg(guarded, effect, 2)],
                     [control])
    assert result.candidates == ()


def test_missing_contract_remains_needs_review_and_records_unknown():
    entry = node("entry", 1, entry=True)
    effect = node("effect", 6, requires_guard="authorization", guarded_value_id="resource")
    result = analyze([entry, effect], [cfg(entry, effect, 1)], [])
    assert result.candidates[0].unknowns == ("guard contract not found",)
    assert result.metrics["peak_memory_bytes"] > 0


def test_renamed_wrapped_inherited_and_overloaded_guards_keep_contract_semantics():
    for name in ("renamed", "Wrapper.check", "BasePolicy.check",
                 "Overloaded.check(java.lang.Object)"):
        entry = node("entry-" + name, 1, entry=True)
        guard = node(name, 3, signature="Policy.requireOwner",
                     checked_value_ids=("resource",))
        effect = node("effect-" + name, 6, requires_guard="authorization",
                      guarded_value_id="resource")
        result = analyze([entry, guard, effect], [cfg(entry, guard, 1), cfg(guard, effect, 2)],
                         [contract()])
        assert result.candidates == ()
        assert len(result.counterevidence) == 1
