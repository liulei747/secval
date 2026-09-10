# ADR 0012: Release quality gate

Status: Accepted for K12, 2026-09-09.

The release gate aggregates every independent blind suite, all five mutation classes, evidence
completeness, unknown explainability, structural duplicate rate, benchmark identifier leakage, wall
time and peak memory. It enforces the release thresholds in the architecture roadmap and requires at
least 24 blind executions.

Performance cannot pass by reducing analysis scope: evaluated scope must be at least the frozen
baseline scope. The current resource budgets are 100 milliseconds maximum analyzer time and 1 MiB
maximum analyzer peak allocation on the synthetic blind suite. These budgets are explicit and can be
versioned when representative production baselines justify a change.

Every run validates external oracle answers against repository commitments and writes a reproducible
artifact containing kernel version, hardware, gate configuration, metrics, thresholds, failed sample
IDs and regression differences. CI runs the contracts, blind evaluators, mutation runner,
anti-overfit scan and release-gate tests.
