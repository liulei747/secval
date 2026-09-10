import json

import pytest

from secval.analyzers import (
    DependencyReachabilityEngine,
    ReachabilityLevel,
    StructuralEngine,
)
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
from secval.frontends import ConfigFactBuilder, DependencyFactBuilder
from secval.semantics import (
    DependencyAdvisory,
    ModelStatus,
    SemanticRegistry,
    StructuralPolicy,
)


def node(store, snapshot, name, kind=NodeKind.CALL, **attributes):
    item = FactNode(stable_node_id("java", kind, name), kind, snapshot,
                    SourceLocation("src/Feature.java", len(store.nodes(snapshot)) + 1),
                    "typed-ast", "1", FactConfidence.PARSER_PROVEN, attributes)
    store.add_node(item)
    return item


def edge(store, snapshot, source, target, kind=EdgeKind.CALLS):
    discriminator = f"{source.id}:{target.id}"
    store.add_edge(FactEdge(stable_edge_id(snapshot, kind, source.id, target.id, discriminator),
                            kind, snapshot, source.id, target.id, "typed-ast",
                            FactConfidence.RESOLVED, target.location,
                            {"discriminator": discriminator}))


def structural_policy():
    return StructuralPolicy("crypto-mode", 1, frozenset({"Crypto.configure(java.lang.String)"}),
                            frozenset({"legacy"}), frozenset({"confidentiality"}),
                            ModelStatus.VERIFIED, ("official:crypto",), "security-team")


def advisory(**changes):
    values = {"id": "ADV-1", "revision": 1, "package": "sample-lib",
              "affected_versions": ">=1.0,<2.0",
              "vulnerable_signatures": frozenset({"sample.Parser.decode(byte[])"}),
              "activation_key": "parser.enabled", "activation_values": frozenset({True}),
              "status": ModelStatus.VERIFIED, "evidence_refs": ("advisory:ADV-1",),
              "approved_by": "security-team"}
    values.update(changes)
    return DependencyAdvisory(**values)


def test_structural_requires_full_signature_dangerous_value_and_sensitive_use():
    store, snapshot = InMemoryFactStore(), "structural"
    value = node(store, snapshot, "mode", NodeKind.VALUE, constant_value="legacy")
    call = node(store, snapshot, "configure", signature="Crypto.configure(java.lang.String)",
                type_name="java.lang.String", usage_context="confidentiality")
    edge(store, snapshot, value, call, EdgeKind.DEFINES_USES)
    result = StructuralEngine(store, SemanticRegistry(structural_policies=[structural_policy()])).analyze(snapshot)
    assert result.candidates[0].kind == CandidateKind.STRUCTURAL
    assert result.candidates[0].path_node_ids == (value.id, call.id)


@pytest.mark.parametrize("changes", [
    {"constant_value": "modern", "usage_context": "confidentiality"},
    {"constant_value": "legacy", "usage_context": "test-fixture"},
    {"constant_value": "legacy", "usage_context": "confidentiality",
     "signature": "Crypto.configure(int)"},
])
def test_structural_safe_context_value_and_overload_do_not_report(changes):
    store, snapshot = InMemoryFactStore(), "safe"
    attributes = {"signature": "Crypto.configure(java.lang.String)", **changes}
    node(store, snapshot, "configure", **attributes)
    result = StructuralEngine(store, SemanticRegistry(structural_policies=[structural_policy()])).analyze(snapshot)
    assert result.candidates == ()


def test_structural_incomplete_constant_propagation_stays_reviewable():
    store, snapshot = InMemoryFactStore(), "unknown"
    node(store, snapshot, "configure", signature="Crypto.configure(java.lang.String)",
         usage_context="confidentiality")
    result = StructuralEngine(store, SemanticRegistry(structural_policies=[structural_policy()])).analyze(snapshot)
    assert result.candidates[0].unknowns == ("constant propagation incomplete",)


def test_structural_value_survives_renamed_wrapper_and_resolved_inheritance():
    store, snapshot = InMemoryFactStore(), "mutated"
    value = node(store, snapshot, "renamedSetting", NodeKind.VALUE, constant_value="legacy")
    wrapper = node(store, snapshot, "renamedWrapper", NodeKind.METHOD)
    inherited_call = node(store, snapshot, "subclassCall",
                          signature="Crypto.configure(java.lang.String)",
                          usage_context="confidentiality", declaring_type="ChildCrypto")
    edge(store, snapshot, value, wrapper, EdgeKind.DEFINES_USES)
    edge(store, snapshot, wrapper, inherited_call, EdgeKind.DEFINES_USES)
    result = StructuralEngine(store, SemanticRegistry(
        structural_policies=[structural_policy()])).analyze(snapshot)
    assert result.candidates[0].path_node_ids == (value.id, wrapper.id, inherited_call.id)


@pytest.mark.parametrize(("format_name", "content", "package"), [
    ("requirements", "sample-lib==1.4.0", "sample-lib"),
    ("package-lock", json.dumps({"dependencies": {"sample-lib": {"version": "1.4.0"}}}), "sample-lib"),
    ("cyclonedx-json", json.dumps({"components": [{"type": "library", "name": "sample-lib", "version": "1.4.0", "purl": "pkg:pypi/sample-lib@1.4.0"}]}), "sample-lib"),
    ("maven-pom", "<project><dependencies><dependency><groupId>org.sample</groupId><artifactId>lib</artifactId><version>1.4.0</version></dependency></dependencies></project>", "org.sample:lib"),
])
def test_dependency_formats_create_versioned_facts(format_name, content, package):
    store = InMemoryFactStore()
    rows = DependencyFactBuilder().build(store, "deps", "manifest", content, format_name)
    assert rows[0].attributes["package"] == package
    assert rows[0].attributes["version"] == "1.4.0"


def dependency_result(version="1.4.0", *, call=True, reachable=True, activation=True):
    store, snapshot = InMemoryFactStore(), "dependency"
    DependencyFactBuilder().build(store, snapshot, "requirements.txt",
                                  f"sample-lib=={version}", "requirements")
    call_node = None
    if call:
        call_node = node(store, snapshot, "decode", signature="sample.Parser.decode(byte[])")
    if reachable:
        entry = node(store, snapshot, "entry", NodeKind.METHOD, external_entry=True)
        if call_node:
            edge(store, snapshot, entry, call_node)
    if activation is not None:
        ConfigFactBuilder().build(store, snapshot, [], environment={"parser.enabled": activation})
    registry = SemanticRegistry(dependency_advisories=[advisory()])
    return DependencyReachabilityEngine(store, registry).analyze(snapshot)


def test_dependency_reaches_all_four_evidence_levels():
    result = dependency_result()
    assert result.assessments[0].level == ReachabilityLevel.RUNTIME_ACTIVATED
    assert result.candidates[0].kind == CandidateKind.DEPENDENCY


def test_unaffected_unreachable_and_disabled_dependencies_are_counterevidence():
    assert dependency_result("2.1.0").candidates == ()
    assert dependency_result(reachable=False).candidates == ()
    assert dependency_result(activation=False).candidates == ()


def test_present_dependency_without_api_and_unknown_activation_are_reviewable():
    missing_api = dependency_result(call=False, reachable=False)
    assert "vulnerable API not observed" in missing_api.candidates[0].unknowns
    unknown_activation = dependency_result(activation=None)
    assert unknown_activation.candidates[0].unknowns == ("runtime activation unknown",)


def test_invalid_or_unlocked_manifest_produces_parse_gap():
    store = InMemoryFactStore()
    assert DependencyFactBuilder().build(store, "deps", "requirements.txt",
                                         "sample-lib>=1", "requirements") == ()
    assert store.gaps("deps")[0].category == "dependency_parse_error"


def test_verified_policies_require_reviewable_evidence():
    with pytest.raises(ValueError):
        StructuralPolicy("p", 1, frozenset({"a"}), frozenset({"b"}), frozenset({"c"}),
                         ModelStatus.VERIFIED)
    with pytest.raises(ValueError):
        advisory(approved_by="llm")
