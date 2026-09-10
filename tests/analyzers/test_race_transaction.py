import pytest

from secval.analyzers import RaceTransactionEngine
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
from secval.semantics import ConcurrencyInvariant, InvariantStatus, SemanticRegistry


def invariant(**changes):
    values = {"id": "inventory.reserve", "revision": 1, "entity": "Inventory",
              "operation": "reserve", "accepted_controls": frozenset({
                  "row_lock", "version_field", "unique_constraint", "atomic_update",
                  "idempotency_key"}),
              "accepted_isolation_levels": frozenset({"serializable"}),
              "requires_transaction": True, "status": InvariantStatus.VERIFIED,
              "evidence_refs": ("database:test",), "approved_by": "data-owner"}
    values.update(changes)
    return ConcurrencyInvariant(**values)


def node(store, snapshot, name, kind=NodeKind.RESOURCE, **attributes):
    row = FactNode(stable_node_id("java", kind, name), kind, snapshot,
                   SourceLocation("src/Inventory.java", len(store.nodes(snapshot)) + 1),
                   "transaction-facts", "1", FactConfidence.PARSER_PROVEN, attributes)
    store.add_node(row)
    return row


def edge(store, snapshot, source, target, kind):
    discriminator = f"{kind}:{target.id}"
    store.add_edge(FactEdge(stable_edge_id(snapshot, kind, source.id, target.id, discriminator),
                            kind, snapshot, source.id, target.id, "transaction-facts",
                            FactConfidence.RESOLVED, target.location,
                            {"discriminator": discriminator}))


def analyze(*, controls=(), isolation="read_committed", transaction=True,
            check=True, same_resource=True, operation_name="renamedReserve"):
    store, snapshot = InMemoryFactStore(), "race"
    operation = node(store, snapshot, operation_name, NodeKind.METHOD, entity="Inventory",
                     operation="reserve", concurrency_controls=controls,
                     isolation_level=isolation)
    resource = node(store, snapshot, "renamedStock")
    other = node(store, snapshot, "otherStock") if not same_resource else resource
    edge(store, snapshot, operation, resource, EdgeKind.READS_RESOURCE)
    if check:
        edge(store, snapshot, operation, resource, EdgeKind.CHECKS_RESOURCE)
    edge(store, snapshot, operation, other, EdgeKind.WRITES_RESOURCE)
    if transaction:
        tx = node(store, snapshot, "wrappedTransaction", NodeKind.METHOD)
        edge(store, snapshot, operation, tx, EdgeKind.IN_TRANSACTION)
    result = RaceTransactionEngine(store, SemanticRegistry(
        concurrency_invariants=[invariant()])).analyze(snapshot)
    return result


def test_unprotected_read_check_write_reports_candidate():
    result = analyze()
    assert result.candidates[0].kind == CandidateKind.RACE_TRANSACTION
    assert "atomic concurrency control missing" in result.assessments[0].violations


@pytest.mark.parametrize("control", ["row_lock", "version_field", "unique_constraint",
                                     "atomic_update", "idempotency_key"])
def test_each_verified_concurrency_control_produces_counterevidence(control):
    result = analyze(controls=(control,))
    assert result.candidates == ()
    assert result.counterevidence[0].accepted_controls == (control,)


def test_serializable_isolation_is_an_accepted_control():
    result = analyze(isolation="serializable")
    assert result.candidates == ()
    assert result.counterevidence[0].accepted_controls == ("isolation:serializable",)


def test_missing_transaction_and_mismatched_resource_are_distinct_violations():
    result = analyze(transaction=False, same_resource=False, controls=("row_lock",))
    assert set(result.assessments[0].violations) == {
        "read-check-write targets differ", "transaction boundary missing"}


def test_missing_check_and_unknown_isolation_remain_reviewable():
    result = analyze(check=False, controls=("row_lock",), isolation=None)
    assert result.candidates[0].unknowns == (
        "resource check fact missing", "runtime isolation level unknown")


def test_renaming_and_transaction_wrapper_do_not_change_evidence():
    left = analyze(controls=("atomic_update",), operation_name="first")
    right = analyze(controls=("atomic_update",), operation_name="second")
    assert bool(left.counterevidence) == bool(right.counterevidence)
    assert left.assessments[0].controls == right.assessments[0].controls


def test_unverified_or_llm_self_approved_invariants_cannot_drive_analysis():
    proposed = invariant(status=InvariantStatus.PROPOSED, evidence_refs=(), approved_by=None)
    result = RaceTransactionEngine(InMemoryFactStore(), SemanticRegistry(
        concurrency_invariants=[proposed])).analyze("x")
    assert result.assessments == ()
    with pytest.raises(ValueError):
        invariant(proposed_by="llm", approved_by="llm")
