# Testing strategy

Testing is organized by claim, not only by crate.

## Layers

- unit tests for local invariants;
- property tests for attenuation, identity, and canonicalization;
- negative fixtures for invalid policy/configuration states;
- adversarial authorization tests;
- state-machine tests;
- deterministic derivation tests;
- mutation tests for critical detectors;
- integration tests through every frontend to prove one dispatcher path;
- replay/TOCTOU tests;
- sandbox escape tests for extension boundaries;
- supply-chain/update tests;
- formal model checks for the smallest high-risk state machines.

## First required proof packages

1. Delegation attenuation.
2. Nested operation re-authorization.
3. Effect lease unforgeability/expiry/audience.
4. Attestation exact-subject binding.
5. Autonomous maintenance cannot widen authority.
6. Conflicting bootstrap claims remain unresolved.
7. Policy/runtime downgrade fails closed.
