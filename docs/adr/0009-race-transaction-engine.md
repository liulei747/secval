# ADR 0009: Race and transaction engine

Status: Accepted for K7, 2026-09-09.

Concurrency analysis consumes explicit READS_RESOURCE, CHECKS_RESOURCE, WRITES_RESOURCE and
IN_TRANSACTION facts. It requires all three resource operations to bind to the same stable resource
identity, so a check for one record cannot protect a write to another.

VERIFIED ConcurrencyInvariant semantics bind an entity operation to accepted controls and isolation
levels. Supported controls include row locks, optimistic version fields, unique constraints, atomic
updates and idempotency keys. A configured serializable isolation level can also satisfy a policy.
LLM-proposed invariants remain PROPOSED until independently evidenced and approved.

Missing transactions, mismatched resources and absent atomic controls produce candidates. Missing
read/check/write facts or unknown runtime isolation remain NEEDS_REVIEW and cannot prove safety.
Valid controls produce location-bound counterevidence. Evidence records every resource access,
transaction boundary, isolation premise, accepted control, violation, unknown, provenance, elapsed
time and peak memory.
