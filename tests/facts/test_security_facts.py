from types import SimpleNamespace

from secval.analyzers import AuthorizationEngine, GuardEngine, TaintEngine
from secval.frontends import FactSnapshotBuilder, JavaSpringSecurityFactBuilder
from secval.semantics import SemanticRegistry
from secval.services.kernel_bootstrap import (
    _java_spring_controls,
    _java_spring_security_models,
)


def chunk(signature, path, content, line=1):
    return SimpleNamespace(
        symbol_names=[signature], chunk_type="method", relative_path=path,
        start_line=line, end_line=line + content.count("\n"), symbol_id=signature,
        content=content,
    )


def test_http_input_reaches_sql_effect_through_cross_method_flow():
    controller = chunk(
        "sample.Controller.search(java.lang.String)", "src/Controller.java",
        '@GetMapping("/search")\nString search(@RequestParam String query) { return service.find(query); }',
    )
    repository = chunk(
        "sample.Repository.find(java.lang.String)", "src/Repository.java",
        "String find(String query) { return statement.executeQuery(query); }",
    )
    calls = [{"caller": controller.symbol_names[0], "callee": repository.symbol_names[0],
              "caller_path": controller.relative_path, "call_line": 2}]
    facts = FactSnapshotBuilder("snap", "java", "parser").build(
        [controller, repository], graph_calls=calls,
    )
    JavaSpringSecurityFactBuilder().build(facts, "snap", [controller, repository], calls)
    result = TaintEngine(
        facts, SemanticRegistry(models=list(_java_spring_security_models())),
    ).analyze("snap", language="java", framework="spring", version="6.0")
    assert result.metrics["sources"] == 1
    assert result.metrics["effects"] == 1
    assert len(result.candidates) == 1
    assert result.candidates[0].taint_kind == "sql"


def test_non_http_method_does_not_become_external_source():
    helper = chunk(
        "sample.Helper.run(java.lang.String)", "src/Helper.java",
        "String run(String value) { return statement.executeQuery(value); }",
    )
    facts = FactSnapshotBuilder("snap", "java", "parser").build([helper])
    JavaSpringSecurityFactBuilder().build(facts, "snap", [helper])
    result = TaintEngine(
        facts, SemanticRegistry(models=list(_java_spring_security_models())),
    ).analyze("snap", language="java", framework="spring", version="6.0")
    assert result.metrics["sources"] == 0
    assert result.metrics["effects"] == 1
    assert result.candidates == ()


def test_client_header_and_path_resource_emit_authorization_candidate():
    controller = chunk(
        "sample.AccountController.read(java.lang.String,java.lang.String)",
        "src/AccountController.java",
        '@GetMapping("/{accountId}")\nObject read(@RequestHeader String requesterId, '
        '@PathVariable String accountId) { return service.read(accountId); }',
    )
    facts = FactSnapshotBuilder("snap", "java", "parser").build([controller])
    JavaSpringSecurityFactBuilder().build(facts, "snap", [controller])
    result = AuthorizationEngine(facts, SemanticRegistry()).analyze("snap")
    assert result.metrics["operations"] == 1
    assert result.metrics["untrusted_principals"] == 1
    assert len(result.candidates) == 1
    assert result.candidates[0].rule_id == "authorization:untrusted-principal"


def test_path_resource_without_client_identity_header_is_not_assumed_untrusted():
    controller = chunk(
        "sample.AccountController.read(java.lang.String)", "src/AccountController.java",
        '@GetMapping("/{accountId}")\nObject read(@PathVariable String accountId) '
        "{ return service.read(accountId); }",
    )
    facts = FactSnapshotBuilder("snap", "java", "parser").build([controller])
    JavaSpringSecurityFactBuilder().build(facts, "snap", [controller])
    assert AuthorizationEngine(facts, SemanticRegistry()).analyze("snap").metrics[
        "operations"] == 0


def test_terminating_identity_mismatch_guard_is_dominating_counterevidence():
    controller = chunk(
        "sample.AccountController.read(java.lang.String,java.lang.String)",
        "src/AccountController.java",
        '@GetMapping("/{accountId}")\nObject read(@RequestHeader String requesterId, '
        '@PathVariable String accountId) { if (!requesterId.equals(accountId)) '
        "{ throw new ForbiddenException(); } return service.read(accountId); }",
    )
    facts = FactSnapshotBuilder("snap", "java", "parser").build([controller])
    JavaSpringSecurityFactBuilder().build(facts, "snap", [controller])
    semantics = SemanticRegistry(controls=list(_java_spring_controls()))
    result = GuardEngine(facts, semantics).analyze("snap")
    assert result.metrics["effects"] == 1
    assert result.metrics["candidates"] == 0
    assert result.metrics["defended"] == 1
    assert result.metrics["bypass_paths"] == 0


def test_explicit_session_verification_upgrades_principal_trust_only():
    controller = chunk(
        "sample.AccountController.read(java.lang.String,java.lang.String)",
        "src/AccountController.java",
        '@GetMapping("/{accountId}")\nObject read(@RequestHeader String authorization, '
        '@PathVariable String accountId) { session.verifySession(authorization); '
        "return service.read(accountId); }",
    )
    facts = FactSnapshotBuilder("snap", "java", "parser").build([controller])
    JavaSpringSecurityFactBuilder().build(facts, "snap", [controller])
    result = AuthorizationEngine(facts, SemanticRegistry()).analyze("snap")
    assert result.metrics["untrusted_principals"] == 0
    assert len(result.candidates) == 1
    assert result.candidates[0].rule_id == "authorization:object-ownership"
