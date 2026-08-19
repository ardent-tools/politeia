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
