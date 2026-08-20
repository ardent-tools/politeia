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

Commissioning, specialization, routing, and handoff use these semantic contracts when transported. Add a dedicated operation only for an institutionally meaningful state transition—for example, deriving a generation or recording handoff—not as a wrapper around a CLI command or provider API.

Discovery and preflight may expose execution requirements and eligible resources. Authorization binds the exact routing decision and selected resource before execution; transport framing may not replace either.

## Disconnected execution

When authorized work must cross a trust-domain or connectivity boundary, the protocol may project
an immutable `ExecutionEnvelope` and accept a bound `ExecutionReceipt`. File bundles, removable
media, queues, HTTP, and human carriage are transports for the same semantics; none becomes a
parallel packet subsystem.

The envelope binds the exact request-body and resolved `OperationSpec` digests, intent,
effect-subject, authority, policy/runtime, operation-specific precondition contract and evaluation,
intended target audience and resource/adapter identities, replay, expiry, and evidence obligations.
Preconditions bind their version, subject, observation time, freshness window, and use-time
revalidation rule. The receipt binds the envelope digest and target-side execution evidence.
Issuance is not proof of execution, receipt absence is not proof of non-execution, and receipt
submission does not retroactively authorize an invalid request.
Delivery state, execution outcome, epistemic resolution, and replay disposition remain independent
typed axes; an execution assessment records them without collapsing one into another.

An envelope is not an `EffectLease`, and no effect port accepts one. The target validates the
envelope's exact bindings plus current revocation, policy/runtime, expiry, precondition, and replay
state, then creates an opaque, single-use `EnvelopeAdmission`. The admission binds the envelope
digest and effect subject to an `OperationIntent` derived exclusively from that envelope, the
current authorization/replay evaluation, and the intended target audience/resource/adapter.

The target dispatcher consumes that admission and atomically records the admission, envelope,
effect-subject, derived-intent, and local lease/reservation identities before invoking an effect
port. Any request, authority, policy/runtime, audience, resource, adapter, or effect-subject
substitution fails closed. Only then may it mint the local audience-bound lease and enter the
protected operation path; minting means the opaque lease is released only after the bound
authorization/reservation state commits. The receipt binds the admission and target-side local
execution evidence; carriage never bypasses complete mediation.

## Protocol rule

Transport adapters may add framing, streaming, authentication carriage, or transport error mapping. They may not reinterpret semantic operation meaning.
