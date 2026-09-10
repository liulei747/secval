# ADR 0006: Effective configuration engine

Status: Accepted for K8, 2026-09-09.

Configuration analysis normalizes YAML, Properties, JSON, XML, TOML and explicitly supplied
runtime values into ConfigNode facts. It refuses to read `.env` files. Each occurrence retains its
raw value, source location, profile, layer and precedence. Higher-priority nodes point to the values
they override, while framework bindings use CONFIGURES, EXPOSES and PROTECTS edges.

Effective value precedence is base, profile, environment, command line and deployment. Callers may
provide explicit numeric precedence for framework-specific layers. Unresolved placeholders and parse
failures become ParseGap facts. They can produce NEEDS_REVIEW candidates but cannot prove safety.

Configuration policies are versioned semantics. A VERIFIED policy requires evidence and approval by
a non-LLM actor, and identifies exact activation, exposure and control keys plus the consuming
component and resource. The engine reports a candidate for an active, exposed resource without its
required control. Evidence includes raw/effective values, override chain, consumer, resource,
controls, deployment premises, locations and unknowns. Metrics record policy and node counts,
candidates, defended combinations, unknown rate, elapsed time and peak memory.
