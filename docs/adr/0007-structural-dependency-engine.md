# ADR 0007: Structural and dependency reachability engines

Status: Accepted for K9, 2026-09-09.

Structural analysis consumes typed AST/CPG facts and VERIFIED exact-signature policies. It follows
DEFINES_USES chains through wrappers, retains the resolved type and constant, and requires a declared
security-sensitive use context. A dangerous literal outside a sensitive use, a safe value, or a
different overload is counterevidence. Missing constant propagation or use context remains a
NEEDS_REVIEW candidate.

Dependency ingestion normalizes pinned Python requirements, npm lockfiles, Maven manifests and
CycloneDX JSON into versioned Dependency nodes. Unsupported or unresolved entries create ParseGap
facts. VERIFIED advisories bind a package/version range to exact vulnerable signatures and optional
runtime activation semantics.

Dependency analysis records four increasing evidence levels: dependency present, vulnerable API
called, externally reachable, and runtime activated. An unaffected version, unreachable vulnerable
call, or disabled runtime path is counterevidence. Missing API facts, unresolved versions and unknown
activation stay reviewable. Both engines emit the shared Candidate contract with node locations,
provenance, assumptions, unknowns, elapsed time and peak memory.
