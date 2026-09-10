from dataclasses import replace

from secval.analyzers import TaintEngine
from secval.candidates import CandidateKind, CandidateStatus
from secval.facts import (
    EdgeKind,
    FactConfidence,
    FactEdge,
    FactNode,
    InMemoryFactStore,
    NodeKind,
    ParseGap,
    SourceLocation,
    stable_edge_id,
    stable_node_id,
)
from secval.semantics import FrameworkModel, ModelKind, ModelStatus, SemanticRegistry

ALL_TESTS = frozenset({"positive", "negative", "wrapper", "inheritance", "overload", "version"})
SNAPSHOT = "snapshot-1"


def semantic(model_id, kind, signature, taint_kinds):
    return FrameworkModel(model_id, 1, "java", "spring", ">=6,<7", kind, signature,
                          ModelStatus.VERIFIED, taint_kinds=frozenset(taint_kinds),
                          test_coverage=ALL_TESTS, evidence_refs=("framework-source",),
                          approved_by="security-maintainer")


def node(name, line, signature=None, **attributes):
    values = {"signature": signature or name, **attributes}
    return FactNode(stable_node_id("java", NodeKind.VALUE, name), NodeKind.VALUE, SNAPSHOT,
                    SourceLocation("src/Sample.java", line), "joern", "4.0",
                    FactConfidence.RESOLVED, values)


def edge(source, target, kind=EdgeKind.DEFINES_USES, **attributes):
    discriminator = f"{source.location.start_line}:{target.location.start_line}:{kind}"
    values = {"discriminator": discriminator, **attributes}
    return FactEdge(stable_edge_id(SNAPSHOT, kind, source.id, target.id, discriminator), kind,
                    SNAPSHOT, source.id, target.id, "joern", FactConfidence.RESOLVED,
                    target.location, values)


def engine(nodes, edges, models, gaps=()):
    store = InMemoryFactStore()
    for item in nodes:
        store.add_node(item)
    for item in edges:
        store.add_edge(item)
    for gap in gaps:
        store.add_gap(gap)
    return TaintEngine(store, SemanticRegistry(models=list(models)))


def source_effect_models(kind="sql"):
    return [semantic("spring.request", ModelKind.SOURCE, "request.value", {kind}),
            semantic("jdbc.execute", ModelKind.EFFECT, "jdbc.execute", {kind})]


def test_bidirectional_interprocedural_path_outputs_evidence_bound_candidate_and_metrics():
    source = node("request", 3, "request.value")
    parameter = node("service.parameter", 8)
    returned = node("repository.return", 13, flow_states=("normalized",))
    effect = node("execute", 18, "jdbc.execute")
    edges = [edge(source, parameter, EdgeKind.ARGUMENT_TO_PARAMETER),
             edge(parameter, returned), edge(returned, effect, EdgeKind.RETURNS_TO)]
    result = engine([source, parameter, returned, effect], edges,
                    source_effect_models()).analyze(
                        SNAPSHOT, language="java", framework="spring", version="6.1")
    assert len(result.candidates) == 1
    candidate = result.candidates[0]
    assert candidate.kind == CandidateKind.TAINT_FLOW
    assert candidate.status == CandidateStatus.NEEDS_REVIEW
    assert candidate.path_node_ids == tuple(item.id for item in [source, parameter, returned, effect])
    assert candidate.flow_states == ("normalized",)
    assert len(candidate.locations) == 4
    assert result.metrics["unknown_rate"] == 0
    assert result.metrics["elapsed_ms"] >= 0
    assert result.metrics["peak_memory_bytes"] > 0


def test_taint_kinds_do_not_semantically_cross():
    source = node("request", 3, "request.value")
    effect = node("execute", 18, "jdbc.execute")
    result = engine([source, effect], [edge(source, effect)],
                    source_effect_models("sql")[:-1] + [
                        semantic("shell.exec", ModelKind.EFFECT, "jdbc.execute", {"shell"})
                    ]).analyze(SNAPSHOT, language="java", framework="spring", version="6.1")
    assert result.candidates == ()


def test_verified_sanitizer_blocks_only_its_applicable_taint_kind():
    source = node("request", 3, "request.value")
    sanitizer = node("sanitize", 8, "sql.parameterize")
    effect = node("execute", 18, "jdbc.execute")
    models = [*source_effect_models(),
              semantic("sql.parameterize", ModelKind.SANITIZER, "sql.parameterize", {"sql"})]
    result = engine([source, sanitizer, effect], [edge(source, sanitizer), edge(sanitizer, effect)],
                    models).analyze(SNAPSHOT, language="java", framework="spring", version="6.1")
    assert result.candidates == ()
    assert len(result.counterevidence) == 1
    assert result.counterevidence[0].control_node_id == sanitizer.id
    assert result.counterevidence[0].locations == (source.location, sanitizer.location)


def test_edge_kind_filter_prevents_unrelated_control_or_call_edges_from_becoming_flow():
    source = node("request", 3, "request.value")
    effect = node("execute", 18, "jdbc.execute")
    for kind in (EdgeKind.CALLS, EdgeKind.CONTROLS):
        result = engine([source, effect], [edge(source, effect, kind)],
                        source_effect_models()).analyze(
                            SNAPSHOT, language="java", framework="spring", version="6.1")
        assert result.candidates == ()


def test_unknown_external_effect_remains_needs_review_with_gap_reason():
    source = node("request", 3, "request.value")
    wrapper = node("client.wrapper", 9)
    gap = ParseGap("gap:external", SNAPSHOT, "missing_dependency", "client library unavailable",
                   SourceLocation("src/Sample.java", 10), "joern", "4.0", "Client.send")
    result = engine([source, wrapper], [edge(source, wrapper)],
                    source_effect_models()[:1], [gap]).analyze(
                        SNAPSHOT, language="java", framework="spring", version="6.1")
    assert len(result.candidates) == 1
    assert result.candidates[0].kind == CandidateKind.UNKNOWN_EFFECT
    assert result.candidates[0].unknowns == ("client library unavailable",)
    assert result.metrics["unknown_rate"] == 1


def test_rename_wrapper_overload_and_inheritance_variants_preserve_graph_result():
    models = source_effect_models()
    for middle_name in ("renamedLocal", "Wrapper.forward", "BaseHandler.handle",
                        "Overloaded.handle(java.lang.String)"):
        source = node("request", 3, "request.value")
        middle = node(middle_name, 8)
        effect = node("execute", 18, "jdbc.execute")
        result = engine([source, middle, effect], [edge(source, middle), edge(middle, effect)],
                        models).analyze(
                            SNAPSHOT, language="java", framework="spring", version="6.1")
        assert len(result.candidates) == 1


def test_unverified_semantic_models_cannot_create_paths():
    source = node("request", 3, "request.value")
    effect = node("execute", 18, "jdbc.execute")
    proposed = replace(source_effect_models()[0], status=ModelStatus.PROPOSED,
                       approved_by=None, test_coverage=frozenset(), evidence_refs=())
    result = engine([source, effect], [edge(source, effect)],
                    [proposed, source_effect_models()[1]]).analyze(
                        SNAPSHOT, language="java", framework="spring", version="6.1")
    assert result.candidates == ()
