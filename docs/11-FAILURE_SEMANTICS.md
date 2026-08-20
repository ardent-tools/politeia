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

## Commissioning, specialization, and routing

- Missing or stale capability evidence, availability, trust-domain identity, or a required locality makes an execution resource ineligible.
- A soft preference never overrides a hard policy, data, capability, budget, or assurance constraint.
- A deterministic-tool requirement never falls back silently to a model. An unsatisfied requirement produces an explicit, evidence-bearing escalation.
- Expired or revoked reconnaissance/commissioner authority blocks new work. Revocation does not disable an already activated operational generation.
- Handoff is incomplete until the operational generation, preserved institution workspace, authority revocation, and continuity evidence are all recorded.
- Generation derivation and activation are atomic. Failure retains the last known good generation; a missing input, provenance record, or reproducibility declaration makes a candidate ineligible.
- Unexpected nondeterminism, institution/workspace mismatch, or cross-institution input quarantines the output rather than activating it.
- No provider, model, hosted service, or commissioner-private system is an implicit fallback.
