# ADR 0004: Guard and dominance analysis

Status: Accepted for K4, 2026-09-09.

The Guard Engine consumes snapshot-scoped facts and VERIFIED Control Contracts. CFG adjacency uses
the explicit `FLOWS_TO` fact edge. The engine computes reachable nodes and iterative dominators from
declared entries, then verifies that a control dominates the sensitive operation, checks the same
resource/value identity, and terminates its failure path according to the contract or parser-proven
branch behavior.

A control is counterevidence only when all three properties hold and no path reaches the operation
while excluding that control. Otherwise the engine records a concrete bypass path and emits a
structured MISSING_GUARD Candidate. Missing control semantics remain NEEDS_REVIEW rather than being
treated as safe. Evidence and counterevidence both retain guard/effect nodes and source locations.

Metrics include sensitive effects, candidates, defended operations, bypass paths, elapsed time, and
peak memory. Blind cases cover missing, effective, and unknown controls; mutation tests cover renamed,
wrapped, inherited, and overloaded control implementations.
