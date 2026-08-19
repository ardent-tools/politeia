# Semantic protocol

The product API is semantic and transport-independent.

MCP, A2A, HTTP/gRPC, CLI, embedded Rust, and future transports adapt to the same operation model.

## Required semantic operations

- `orient(intent, context)` — produce minimal applicable institutional context and missing axes.
- `discover(intent, context)` — discover capabilities, knowledge, requirements, and candidate operations.
- `inspect(subject)` — read authorized institutional state.
- `propose_model(observations)` — propose institutional facts/relationships without self-approving them.
- `preflight(operation_intent)` — return applicability, required authority, effects, budgets, evidence obligations, and likely denials.
- `authorize(operation_intent)` — obtain a normalized decision and, when allowed, an effect lease.
- `execute(authorized_operation)` — invoke one bounded operation.
- `submit_evidence(evidence)` — add provenance-bearing evidence.
- `verify(subject, obligations)` — run or request designated verification.
- `attest(verification)` — bind verified subject and exact environment identities.
- `observe(event_or_friction)` — create learning input.
- `propose_change(change)` — propose policy/knowledge/runbook/system improvement.
- `request_waiver(binding, scope, reason)` — request explicit exception through proper authority.

## Protocol rule

Transport adapters may add framing, streaming, authentication carriage, or transport error mapping. They may not reinterpret semantic operation meaning.
