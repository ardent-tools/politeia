# Failure semantics

Every protected operation specifies:

- whether denial/failure is fail-closed;
- timeout behavior;
- retry policy;
- idempotency key semantics;
- compensation/recovery;
- partial-failure behavior;
- evidence durability requirement;
- maximum resource/cost budget;
- external side-effect replay semantics.

Default for privileged or destructive operations is fail-closed.

Retryable writes require idempotency or an explicit compensation model.

Unknown policy state, stale runtime identity, expired delegation, or mismatched attestation subject may not silently degrade to permission.

## Ambiguous effect execution

Delivery state, execution outcome, epistemic resolution, and replay disposition are separate
facts. Issuing, transferring, or acknowledging an `ExecutionEnvelope` does not establish whether
its effect ran. Until a bound receipt or authoritative target observation establishes the outcome,
no outcome is recorded, epistemic resolution remains unresolved, and replay disposition remains
blocked; none may be mapped to not-executed, failed, or safe-to-retry.

Before reissuing, the system canonically derives the effect subject from target, resolved
operation, resource set, and normalized effect-defining parameters, then tests overlap against
prior issued work. Uncertain equivalence fails closed instead of minting a fresh local subject. If
an overlapping outcome is unresolved, replay is allowed only when policy has
evidence that the exact target enforces the declared idempotency key/body/scope/window, or after an
authorized reconciliation or compensation. A locally generated identifier does not make a target
idempotent.

A blocked ambiguity exposes a transport-neutral `SemanticClosure`: for example, obtain the target
receipt, perform a read-only reconciliation, request an authorized human decision, or run an
approved compensation. The effect state machine must define legal ambiguity and reconciliation
transitions before the disconnected path is implemented.

Operation-specific readiness and precondition evidence are distinct from effect authorization,
recovery, and compensation. Unknown required state blocks an irreversible effect unless an
authorized policy explicitly admits that uncertainty; the existence of a backup changes risk, not
authority. A precondition binds its predicate/version, subject, observation time, freshness window,
and use-time revalidation rule. Observing it requires authority but does not grant effect authority;
the target revalidates stale or use-time-sensitive predicates atomically with the effect where its
boundary permits. If the target cannot enforce the required freshness and atomicity, it blocks the
effect.

## Commissioning, specialization, and routing

- Missing or stale capability evidence, availability, trust-domain identity, or a required locality makes an execution resource ineligible.
- A soft preference never overrides a hard policy, data, capability, budget, or assurance constraint.
- A deterministic-tool requirement never falls back silently to a model. An unsatisfied requirement produces an explicit, evidence-bearing escalation.
- Expired or revoked reconnaissance/commissioner authority blocks new work. Revocation does not disable an already activated operational generation.
- Handoff is incomplete until the operational generation, preserved institution workspace, authority revocation, and continuity evidence are all recorded.
- Generation derivation and activation are atomic. Failure retains the last known good generation; a missing input, provenance record, or reproducibility declaration makes a candidate ineligible.
- The system quarantines output on undeclared nondeterminism, institution/workspace mismatch, or cross-institution input; it does not activate that output.
- No provider, model, hosted service, or commissioner-private system is an implicit fallback.
