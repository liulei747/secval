# ADR 0011: Incremental kernel runtime migration

Status: Accepted for K11, 2026-09-09.

The migration runtime executes registered kernel analyzers under a shared task budget while the
legacy audit continues to produce bootstrap hints. Kernel and legacy metrics remain separate, and a
legacy hint has no route into CandidateLedger or a confirmed verdict.

Analyzer completion and every candidate are checkpointed independently. Resume skips completed
analyzers, preserves candidate IDs and legacy hint IDs, and rejects a different snapshot. A copy-only
historical report adapter preserves schema-v3 output without allowing the kernel view to rewrite it.
The bridge adds kernel state and a read-only marker to existing audit tasks while retaining all old
report fields.

This boundary supports gradual analyzer wiring into repository-specific fact builders. The runtime
itself depends only on analyzer result contracts, CandidateLedger and the existing task store update
interface.
