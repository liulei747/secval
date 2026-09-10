# ADR 0002: Versioned semantic registry and approval boundary

Status: Accepted for K2, 2026-09-09.

Framework models use controlled kinds for Source, Effect, Propagator, Sanitizer, Validator,
authentication context, transaction, and ORM semantics. A model is scoped as generic, framework,
or project; project scope wins for the same kind and full signature, followed by framework and
generic scope. Equal scope, version, revision, kind, and signature with different content is a hard
conflict rather than an arbitrary winner.

VERIFIED models require evidence, a non-LLM approver, and positive, negative, wrapper, inheritance,
overload, and version tests. An LLM-originated item can only be PROPOSED. Version expressions are
explicit bounded comparisons; unsupported expressions fail closed.

Control contracts record input/output flow states, applicable taint kinds, acceptance conditions,
and failure behavior. Business invariants use append-only revisions with PROPOSED, VERIFIED, and
REJECTED lifecycle states. VERIFIED controls and invariants require evidence and non-LLM approval.
