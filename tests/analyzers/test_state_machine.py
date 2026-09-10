import pytest

from secval.analyzers import StateMachineEngine
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
from secval.semantics import InvariantStatus, SemanticRegistry, StateTransitionInvariant


def invariant(**changes):
    values = {"id": "fulfillment.approve", "revision": 1, "entity": "Fulfillment",
              "operation": "approve", "allowed_from": frozenset({"pending"}),
              "allowed_to": frozenset({"approved"}),
              "required_conditions": frozenset({"reviewed"}), "repeatable": False,
              "required_side_effects": frozenset({"audit-recorded"}),
              "status": InvariantStatus.VERIFIED, "evidence_refs": ("workflow:test",),
              "approved_by": "domain-owner"}
    values.update(changes)
    return StateTransitionInvariant(**values)


def add_node(store, snapshot, name, kind, **attributes):
    row = FactNode(stable_node_id("java", kind, name), kind, snapshot,
                   SourceLocation("src/Workflow.java", len(store.nodes(snapshot)) + 1),
                   "state-facts", "1", FactConfidence.PARSER_PROVEN, attributes)
    store.add_node(row)
    return row


def add_edge(store, snapshot, source, target, kind):
    discriminator = f"{source.id}:{target.id}"
    store.add_edge(FactEdge(stable_edge_id(snapshot, kind, source.id, target.id, discriminator),
                            kind, snapshot, source.id, target.id, "state-facts",
                            FactConfidence.RESOLVED, target.location,
                            {"discriminator": discriminator}))


def analyze(*, source="pending", target="approved", conditions=("reviewed",),
            effects=("audit-recorded",), may_repeat=False, idempotency=None,
            initial_state_known=True, operation_name="renamedMethod"):
    store, snapshot = InMemoryFactStore(), "state"
    read = add_node(store, snapshot, "renamedRead", NodeKind.STATE, state=source)
    operation = add_node(store, snapshot, operation_name, NodeKind.METHOD,
                         entity="Fulfillment", operation="approve", preconditions=conditions,
                         may_repeat=may_repeat, idempotency_control=idempotency,
                         initial_state_known=initial_state_known)
    write = add_node(store, snapshot, "renamedWrite", NodeKind.STATE, state=target)
    add_edge(store, snapshot, operation, read, EdgeKind.READS_STATE)
    add_edge(store, snapshot, operation, write, EdgeKind.WRITES_STATE)
    for index, effect_name in enumerate(effects):
        effect = add_node(store, snapshot, f"wrappedEffect{index}", NodeKind.RESOURCE,
                          effect=effect_name)
        add_edge(store, snapshot, operation, effect, EdgeKind.CAUSES_EFFECT)
    registry = SemanticRegistry(state_invariants=[invariant()])
    return StateMachineEngine(store, registry).analyze(snapshot)


def test_valid_transition_with_precondition_and_side_effect_is_counterevidence():
    result = analyze()
    assert result.candidates == ()
    assert len(result.counterevidence) == 1


@pytest.mark.parametrize(("changes", "violation"), [
    ({"source": "draft"}, "source state not allowed"),
    ({"target": "completed"}, "target state not allowed"),
    ({"conditions": ()}, "required precondition missing"),
    ({"effects": ()}, "required side effect missing"),
    ({"may_repeat": True}, "non-repeatable operation can execute repeatedly"),
])
def test_invalid_transitions_report_precise_violation(changes, violation):
    result = analyze(**changes)
    assert result.candidates[0].kind == CandidateKind.STATE_MACHINE
    assert violation in result.assessments[0].violations


def test_idempotency_control_refutes_repeat_execution_risk():
    assert analyze(may_repeat=True, idempotency="request-key").candidates == ()


def test_unknown_initial_state_remains_reviewable():
    result = analyze(initial_state_known=False)
    assert result.candidates[0].unknowns == ("initial state unknown",)


def test_renaming_and_wrapper_nodes_do_not_change_transition_semantics():
    first = analyze(operation_name="firstName")
    second = analyze(operation_name="secondName")
    assert bool(first.counterevidence) == bool(second.counterevidence)
    assert first.assessments[0].from_state == second.assessments[0].from_state


def test_proposed_and_llm_invariants_cannot_drive_analysis_or_self_approve():
    proposed = invariant(status=InvariantStatus.PROPOSED, evidence_refs=(), approved_by=None)
    store = InMemoryFactStore()
    result = StateMachineEngine(store, SemanticRegistry(state_invariants=[proposed])).analyze("x")
    assert result.assessments == ()
    with pytest.raises(ValueError):
        invariant(proposed_by="llm", approved_by="llm")
