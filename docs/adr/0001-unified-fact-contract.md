# ADR 0001: Unified fact identity and snapshot boundary

Status: Accepted for the K1 migration slice, 2026-09-09.

## Decision

Security analyzers consume `FactReader` and the immutable `FactNode`, `FactEdge`,
`SourceLocation`, and `ParseGap` records in `secval.facts`. A fact records code or deployment
structure only; it cannot carry a vulnerability verdict.

Node identity is derived from language, controlled node kind, and a fully qualified symbol. The
identity remains stable when the same source snapshot is rebuilt. `snapshot_id` is a separate part
of every storage key, so equal symbols in different snapshots cannot connect. Edge identity includes
the snapshot, controlled edge kind, both endpoint IDs, and an optional deterministic discriminator.

Every node and edge has a source location, origin, confidence, and parser version where applicable.
Frontends must emit a `ParseGap` for missing dependencies, unresolved dynamic dispatch, reflection,
native code, unsupported syntax, or failed parsing. A missing edge is therefore not evidence that a
relationship is absent.

## Initial edge vocabulary

The first contract supports `CALLS`, `ARGUMENT_TO_PARAMETER`, `RETURNS_TO`, `DEFINES_USES`,
`CONTROLS`, `OVERRIDES`, `CONFIGURES`, `EXPOSES`, and `PROTECTS`. Frontend-specific labels must be
translated at the adapter boundary. Adding an edge kind requires contract tests and a documented
security-analysis consumer; arbitrary strings are rejected.

## Migration

`InMemoryFactStore` is the reference implementation and contract test fixture. Joern, Neo4j, and
Tree-sitter adapters will be added behind `FactReader`; existing graph storage remains operational
until adapter parity and blind/mutation gates pass.

The K1 implementation now provides adapters for existing Tree-sitter chunks, Neo4j call rows, and
Joern data-flow paths. `FactSnapshotBuilder` materializes them into one store, converts unresolved
call endpoints and dynamic calls into visible gaps, reports coverage by gap category, and invalidates
only the exact snapshot before rebuilding a changed source or dependency closure. Runtime cutover is
deferred to K11; analyzers can start against `FactReader` without importing infrastructure clients.
