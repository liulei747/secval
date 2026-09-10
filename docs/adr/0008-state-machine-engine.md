# ADR 0008: Business state-machine engine

Status: Accepted for K6, 2026-09-09.

State analysis consumes explicit state reads, operations, state writes and side-effect facts. The
fact graph uses READS_STATE, WRITES_STATE and CAUSES_EFFECT edges, so identifier renaming and method
wrapping do not alter transition meaning.

VERIFIED StateTransitionInvariant semantics identify the entity and operation, allowed source and
target states, required preconditions, repeatability and required side effects. LLM-proposed
invariants remain PROPOSED until supported by code, tests, documentation or human approval.

The engine detects disallowed source or target states, missing preconditions, missing side effects
and repeatable execution of a non-repeatable operation without an idempotency control. Unknown
initial or target state remains NEEDS_REVIEW. Valid transitions and effective idempotency controls
produce location-bound counterevidence. Results retain entity, operation, transition, conditions,
side effects, controls, violations, unknowns, provenance, elapsed time and peak memory.
