
import pytest

from secval.analyzers import ConfigurationEngine
from secval.candidates import CandidateKind, CandidateStatus
from secval.facts import (
    EdgeKind,
    FactConfidence,
    FactNode,
    InMemoryFactStore,
    NodeKind,
    SourceLocation,
    stable_node_id,
)
from secval.frontends import ConfigFactBuilder, ConfigLayer, ConfigRelation
from secval.semantics import ConfigurationPolicy, ModelStatus, SemanticRegistry


def policy(**changes):
    values = {"id": "remote-console", "revision": 1,
              "activation_key": "feature.console.enabled",
              "activation_values": frozenset({True, "true"}),
              "exposure_key": "server.bind", "exposure_values": frozenset({"0.0.0.0"}),
              "control_key": "feature.console.auth",
              "safe_control_values": frozenset({True, "true"}),
              "consumer": "ConsoleServer.start()", "resource": "management-console",
              "status": ModelStatus.VERIFIED, "evidence_refs": ("official:console",),
              "approved_by": "security-team"}
    values.update(changes)
    return ConfigurationPolicy(**values)


def analyze(layers, **runtime):
    store = InMemoryFactStore()
    ConfigFactBuilder().build(store, "snap", layers, **runtime)
    registry = SemanticRegistry()
    registry.register_configuration_policy(policy())
    return store, ConfigurationEngine(store, registry).analyze("snap")


@pytest.mark.parametrize(("format_name", "content"), [
    ("yaml", "feature:\n  console:\n    enabled: true\n    auth: false\nserver:\n  bind: 0.0.0.0\n"),
    ("json", '{"feature":{"console":{"enabled":true,"auth":false}},"server":{"bind":"0.0.0.0"}}'),
    ("toml", '[feature.console]\nenabled=true\nauth=false\n[server]\nbind="0.0.0.0"\n'),
    ("properties", "feature.console.enabled=true\nfeature.console.auth=false\nserver.bind=0.0.0.0\n"),
    ("xml", "<config><feature><console><enabled>true</enabled><auth>false</auth></console></feature><server><bind>0.0.0.0</bind></server></config>"),
])
def test_formats_create_equivalent_configuration_candidates(format_name, content):
    store = InMemoryFactStore()
    ConfigFactBuilder().build(store, "snap", [ConfigLayer("base", format_name,
                                                          f"application.{format_name}", content, 100)])
    registry = SemanticRegistry(configuration_policies=[policy()])
    result = ConfigurationEngine(store, registry).analyze("snap")
    assert len(result.candidates) == 1
    assert result.candidates[0].kind == CandidateKind.CONFIGURATION
    assert result.candidates[0].status == CandidateStatus.NEEDS_REVIEW


def test_precedence_override_chain_and_safe_control_are_counterevidence():
    base = ConfigLayer("base", "yaml", "application.yml",
                       "feature:\n  console:\n    enabled: false\n    auth: false\nserver:\n  bind: 127.0.0.1\n", 100)
    profile = ConfigLayer("profile", "properties", "application-prod.properties",
                          "feature.console.enabled=true\nserver.bind=0.0.0.0", 200, "prod")
    store, result = analyze([base, profile], environment={"feature.console.auth": "false"},
                            cli={"feature.console.auth": "true"})
    assert result.candidates == ()
    assert len(result.counterevidence) == 1
    evidence = result.counterevidence[0]
    assert dict(evidence.effective_values)["feature.console.auth"] == "true"
    assert len(store.edges("snap", kind=EdgeKind.OVERRIDES)) == 4


def test_deployment_override_is_effective_and_reported():
    base = ConfigLayer("base", "properties", "application.properties",
                       "feature.console.enabled=false\nfeature.console.auth=false\nserver.bind=127.0.0.1", 100)
    _, result = analyze([base], deployment={"feature.console.enabled": "true",
                                            "server.bind": "0.0.0.0"})
    assert len(result.candidates) == 1
    assert result.assessments[0].deployment_premises


def test_unresolved_and_missing_values_remain_reviewable():
    layer = ConfigLayer("base", "yaml", "application.yml",
                        "feature:\n  console:\n    enabled: ${CONSOLE_ENABLED}\nserver:\n  bind: 0.0.0.0\n", 100)
    store, result = analyze([layer])
    assert len(result.candidates) == 1
    assert result.candidates[0].unknowns == (
        "effective value unresolved: feature.console.enabled",
        "effective value missing: feature.console.auth")
    assert {gap.category for gap in store.gaps("snap")} == {"unresolved_config_value"}


@pytest.mark.parametrize("kind", [EdgeKind.CONFIGURES, EdgeKind.EXPOSES, EdgeKind.PROTECTS])
def test_relationships_connect_effective_config_to_existing_consumers_and_resources(kind):
    store = InMemoryFactStore()
    resource_id = stable_node_id("java", NodeKind.RESOURCE, "console")
    store.add_node(FactNode(resource_id, NodeKind.RESOURCE, "snap", SourceLocation("App.java", 3),
                            "tree-sitter", "1", FactConfidence.PARSER_PROVEN, {}))
    ConfigFactBuilder().build(store, "snap", [ConfigLayer(
        "base", "properties", "application.properties", "server.bind=0.0.0.0", 100)],
        relations=[ConfigRelation("server.bind", resource_id, kind)])
    assert store.edges("snap", kind=kind)[0].target_id == resource_id


def test_parser_failure_is_visible_and_dotenv_read_is_rejected():
    store = InMemoryFactStore()
    ConfigFactBuilder().build(store, "snap", [ConfigLayer("base", "json", "broken.json", "{", 100)])
    assert store.gaps("snap")[0].category == "config_parse_error"
    with pytest.raises(ValueError, match="不读取.env"):
        ConfigFactBuilder().build(store, "other", [ConfigLayer("base", "properties", ".env", "A=B", 100)])


def test_verified_policy_requires_evidence_and_non_llm_approval():
    with pytest.raises(ValueError):
        policy(evidence_refs=())
    with pytest.raises(ValueError):
        policy(approved_by="llm")
