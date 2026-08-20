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

## Bounded commissioning acceptance suite

The first proof must implement the `POL-A` through `POL-L` claims registered in `12-ASSURANCE_CASE.md`, using only one institution workspace, adapter, approval, generation, handoff/revocation, and a two-resource routing fixture.

- `POL-A`: commission in a clean client-controlled fixture from public source, then emit exact generation and handoff receipts.
- `POL-B`: prove no client secret, state, log, or inference request enters a commissioner store; revoke the commissioner and run an operational canary.
- `POL-C`: remove reconnaissance, authoring, and commissioner authority at handoff while the activated operational generation continues.
- `POL-D`: derive twice from identical canonical generation inputs, including the preserved commissioning record, and compare exact bytes and digest; mutate each bound input and require a different identity. Any allowed nondeterminism has a machine-readable contract.
- `POL-E`: with two resources, prove all hard constraints filter first, then the declared cost/locality order selects among survivors; no survivor produces typed escalation and reasons.
- `POL-F`: make the higher-scoring remote resource ineligible for local-only data and assert its provider port is never called.
- `POL-G`: for a verified deterministic task, select the tool and assert every model port has zero calls.
- `POL-H`: property-test that calibration changes eligibility only, never delegation, policy, waiver, or verifier independence.
- `POL-I`: derive disjoint generations from two workspaces and prove neither private input appears in the other's dependency closure.
- `POL-J`: recommission with a newly authorized maintainer that has no original commissioner identity or account.
- `POL-K`: build and exercise the proof with all commissioner-controlled or otherwise institution-external integrations absent.
- `POL-L`: disconnect vendor endpoints and prove policy, execution, evidence, verification, the current generation, and an authorized local update path remain available.

Each claim needs a positive case, a negative/adversarial case, and an explicit falsifier. Receipts bind the exact source, workspace, generation, policy, lifecycle, execution-resource, adapter, and harness identities. Unit tests may prove typed invariants; physical custody, network disconnection, account replacement, and clean-machine operation require deployment evidence and may not be claimed from an in-memory fixture.
