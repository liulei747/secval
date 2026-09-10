# ADR 0003: Kind-aware bidirectional taint/effect engine

Status: Accepted for K3, 2026-09-09.

The Taint Engine consumes only `FactReader` and `SemanticRegistry`. VERIFIED Source, Effect, and
Sanitizer models select nodes by full signature. Forward reachability starts at each Source while
reverse reachability starts at each Effect; a candidate requires their intersection for the same
taint kind. Flow uses only argument-to-parameter, return-to, and definition-use edges. Ordinary
call and control edges cannot create data flow.

Candidates use the unified structured identity and bind every path node to a source location.
Flow states remain ordered evidence on the candidate. A VERIFIED sanitizer blocks only its declared
taint kinds and produces located counterevidence. Missing dependencies, dynamic dispatch, and native
boundaries reached by tainted data produce UNKNOWN_EFFECT candidates in NEEDS_REVIEW.

The engine reports source/effect/candidate counts, blocked flows, unknown rate, elapsed time, and
peak memory. The K3 blind set covers a supported path, an effective sanitizer, and an unknown
external effect; mutation tests cover rename, wrapper, inheritance, and overload shapes.
