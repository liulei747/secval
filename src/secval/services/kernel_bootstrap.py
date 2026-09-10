"""Production lifecycle assembly for the incrementally migrated analysis kernel."""

import hashlib
import json
from pathlib import Path

from secval.analyzers import (
    AuthorizationEngine,
    ConfigurationEngine,
    DependencyReachabilityEngine,
    GuardEngine,
    RaceTransactionEngine,
    StateMachineEngine,
    StructuralEngine,
    TaintEngine,
)
from secval.facts import InMemoryFactStore
from secval.frontends import ConfigFactBuilder, ConfigLayer, FactSnapshotBuilder
from secval.semantics import ConfigurationPolicy, ModelStatus, SemanticRegistry
from secval.services.kernel_runtime import (
    KernelCheckpointStore,
    KernelMigrationRuntime,
    publish_kernel_failure,
    publish_kernel_state,
)


def _closure_hash(task):
    scope = task.get("scope", {})
    payload = {
        "repository_id": task.get("repository_id"),
        "snapshot_id": task.get("snapshot_id"),
        "source_snapshot_id": scope.get("source_snapshot_id"),
        "index_run_id": scope.get("index_run_id"),
        "scope_paths": task.get("scope_paths", []),
        "approved_config_paths": task.get("approved_config_paths", []),
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()


def create_kernel_runner(database_path, analyzer_factory=None, source_store=None, graph_store=None):
    """Return the post-legacy dual-run hook used by AuditService.

    The factory boundary lets production fact/semantic assembly evolve without
    coupling AuditService to an analyzer or graph implementation.
    """
    checkpoint_path = Path(database_path).with_name("kernel-checkpoints.json")

    def run(store, task_id):
        task = store.get(task_id)
        analyzers = tuple(analyzer_factory(task) if analyzer_factory
                          else production_analyzers(task, source_store=source_store,
                                                    graph_store=graph_store))
        runtime = KernelMigrationRuntime(
            analyzers, checkpoint_store=KernelCheckpointStore(checkpoint_path)
        )
        try:
            result = runtime.run(
                task_id, task["snapshot_id"], _closure_hash(task),
                budget=len(analyzers), legacy_hints=task.get("path_sketches", ()),
                tool_versions=("kernel-runtime@1",),
            )
            publish_kernel_state(store, task_id, result)
        except Exception as error:
            publish_kernel_failure(store, task_id, error)

    return run


class _TaintInvocation:
    runtime_name = "TaintEngine"

    def __init__(self, engine, task):
        self.engine, self.task = engine, task

    def analyze(self, snapshot_id):
        return self.engine.analyze(
            snapshot_id, language="java", framework="spring", version="6.0",
            project_id=self.task.get("repository_id"),
        )


def _spring_configuration_policies():
    common = {"revision": 1, "status": ModelStatus.VERIFIED,
              "evidence_refs": ("spring-boot-reference",),
              "approved_by": "secval-builtin-review"}
    return (
        ConfigurationPolicy(
            id="spring-h2-console", activation_key="spring.h2.console.enabled",
            activation_values=frozenset({True, "true"}),
            exposure_key="spring.h2.console.enabled", exposure_values=frozenset({True, "true"}),
            control_key="spring.h2.console.settings.web-allow-others",
            safe_control_values=frozenset({False, "false"}), consumer="H2ConsoleAutoConfiguration",
            resource="h2-console", **common),
        ConfigurationPolicy(
            id="spring-actuator-wildcard", activation_key="management.endpoints.web.exposure.include",
            activation_values=frozenset({"*"}), exposure_key="management.endpoints.web.exposure.include",
            exposure_values=frozenset({"*"}), control_key="management.server.address",
            safe_control_values=frozenset({"127.0.0.1", "localhost"}),
            consumer="WebEndpointAutoConfiguration", resource="actuator-endpoints", **common),
        ConfigurationPolicy(
            id="spring-error-stacktrace", activation_key="server.error.include-stacktrace",
            activation_values=frozenset({"always"}), exposure_key="server.error.include-stacktrace",
            exposure_values=frozenset({"always"}), control_key="server.error.path",
            safe_control_values=frozenset({"never"}), consumer="BasicErrorController",
            resource="error-response", **common),
    )


def _build_facts(task, source_store, graph_store):
    facts = InMemoryFactStore()
    if source_store is None:
        return facts
    source_snapshot_id = task.get("scope", {}).get("source_snapshot_id")
    if not source_snapshot_id:
        return facts
    from secval.code_processing.repository_processing.process_repository import process_repository
    from secval.models.identifiers import RepositoryId, SnapshotId
    with source_store.indexing_directory(source_snapshot_id) as directory:
        processed = process_repository(
            directory, RepositoryId(task["repository_id"]), SnapshotId(task["snapshot_id"]))
    language = next((row.language for row in processed.chunks), "java")
    graph_calls = ()
    index_run_id = task.get("scope", {}).get("index_run_id")
    if graph_store is not None and index_run_id:
        graph_calls = graph_store.export_calls(
            task["repository_id"], task["snapshot_id"], index_run_id)
    FactSnapshotBuilder(task["snapshot_id"], language, "repository-parser@1", store=facts).build(
        processed.chunks, graph_calls=graph_calls,
        parse_failures=((row.relative_path, row.message) for row in processed.errors),
    )
    layers = []
    formats = {".yml": "yaml", ".yaml": "yaml", ".json": "json",
               ".toml": "toml", ".properties": "properties"}
    for path, _, content in source_store.iter_captured_files(source_snapshot_id):
        format_name = formats.get(Path(path).suffix.lower())
        if format_name and (path.startswith("src/main/resources/") or path in task.get("approved_config_paths", ())):
            layers.append(ConfigLayer("base", format_name, path, content, 100))
    ConfigFactBuilder().build(facts, task["snapshot_id"], layers)
    return facts


def production_analyzers(task, *, source_store=None, graph_store=None):
    """Assemble every production analyzer over the task-scoped fact boundary.

    Fact ingestion is deliberately isolated here. Until persistent frontend
    facts are supplied, an empty store yields explicit zero-coverage metrics;
    it never promotes a legacy/model hint into a kernel verdict.
    """
    facts = _build_facts(task, source_store, graph_store)
    semantics = SemanticRegistry(configuration_policies=list(_spring_configuration_policies()))
    return (
        _TaintInvocation(TaintEngine(facts, semantics), task),
        GuardEngine(facts, semantics),
        AuthorizationEngine(facts, semantics),
        ConfigurationEngine(facts, semantics),
        StructuralEngine(facts, semantics),
        DependencyReachabilityEngine(facts, semantics),
        StateMachineEngine(facts, semantics),
        RaceTransactionEngine(facts, semantics),
    )
