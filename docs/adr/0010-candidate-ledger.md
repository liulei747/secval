# ADR 0010: Candidate adjudication ledger

Status: Accepted for K10, 2026-09-09.

Candidate identity is derived from rule, snapshot, entry, operation, resource and root cause. Path
variants with the same identity merge while retaining every analyzer record. Different resources or
root causes remain separate.

The ledger is append-only and hash chained. Every event records a six-state verdict, reason,
evidence IDs, tool versions, dependency-closure hash, timestamp and prior event hash. CONFIRMED,
REJECTED, UNREACHABLE, DEFENDED and DUPLICATE each enforce their evidence premise. A changed code,
dependency or control closure appends NEEDS_REVIEW rather than rewriting history.

NeedPlanner turns candidate unknowns into bounded requests targeting an existing entry or operation
node. CounterevidenceRunner accepts only known evidence classes with a snapshot and explicit path
coverage. Reports are deterministic Ledger views; prose or model output cannot set a finding state.
