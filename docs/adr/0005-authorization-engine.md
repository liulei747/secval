# ADR 0005: Principal-resource authorization engine

Status: Accepted for K5, 2026-09-09.

Authorization analysis consumes domain facts for Principal, Resource, and Operation and reuses
Guard Engine evidence. A principal is classified as server-authenticated, client-controlled, or
unknown. Client headers and request parameters cannot become trusted principals merely because a
guard compares them with a resource field.

Operations declare required ownership, tenant, role, or permission constraints and bind the exact
principal/resource node IDs. A constraint is proven only by a dominating, same-resource,
failure-terminating Guard whose fact declares that constraint. Ownership, tenant boundary,
functional role, and permission failures remain distinct rules. Missing principal, resource, trust,
or control semantics produce NEEDS_REVIEW candidates rather than a safe result.

Evidence records principal trust, operation, required/proven/missing constraints, guard nodes, and
locations. Metrics cover operations, candidates, defended operations, untrusted principals, unknown
rate, elapsed time, and peak memory. Nested analyzer memory tracing has explicit ownership so Guard
analysis cannot erase Authorization metrics.
