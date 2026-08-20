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

## Follow-on proof packages

`POL-O` closes Phase 0 for the first enforced control. The phase-owned `POL-M`, `POL-N`, `POL-P`,
and `POL-Q` claims refine later acceptance and do not expand the smaller `POL-A` through `POL-L`
commissioning slice. Each public contract requires its proof package before implementation credit:

- `POL-M`: vary delivery state, execution outcome, epistemic resolution, and replay disposition
  independently. Issue an immutable envelope, withhold outcome evidence, and prove an overlapping
  at-most-once effect has no invented outcome, remains epistemically unresolved, and stays blocked.

  - Prove alternate encodings and fresh local IDs cannot evade canonical overlap. Prove a repeat
    only when an exact target idempotency contract covers the same effect subject, request body, key
    scope, and retention window.
  - Expire a bound precondition before use and require target-side revalidation. Reject wrong
    audience, resource, or adapter identities and a revoked authority at the target.
  - Prove an effect port cannot consume an envelope directly. The target dispatcher creates and
    consumes the single-use admission, derives the intent exclusively from the exact envelope,
    reauthorizes current state, and atomically binds admission/envelope/effect-subject to the local
    lease reservation before releasing the lease or invoking the port. Consume the same admission
    twice and require the second attempt to fail with an unchanged port call count.
  - Validate one envelope and attempt to mint for a substituted request, authority, policy/runtime,
    audience, resource, adapter, or effect subject; require rejection with port call count zero.
    Drift revocation or policy/runtime state between issue and target authorization and require the
    same failure.
  - Bind a later receipt to the admission and local execution evidence.
- `POL-N`: present an eligible source object that a faulty recognizer would omit and require the
  membership proof to fail before projection. Present an included member without its required
  contract and require an attributable derivation failure. Then use equal-sized but differently
  identified source/output populations and require the identity-set comparison to fail.
- `POL-O`: send known-good and planted-bad inputs through the actual mediation path and bind the
  observed clean/refusal result to the exact control, path, subject, and population. Submit a
  forged `clean` without activation or coverage evidence and require assurance aggregation to
  reject it. Exercise `violation`, `not_run`, `unavailable`, `unevaluable`, `unexpectedly_empty`,
  `not_applicable`, and `unresolved` independently; preserve each distinction and prove none can
  aggregate as clean.
- `POL-P`: deliver or attest artifact `A`, append a correction and a superseding `B`, and prove
  `A`'s bytes/digest remain unchanged while the current interpretation is reproducible from the
  admitted records. Add two competing live successors and a supersession cycle; both project to an
  explicit unresolved current assessment. Arbitrary timestamp precedence is invalid.
- `POL-Q`: offer a highly relevant unauthorized source and a weaker authorized source; the former
  never enters the ranking set. For a current-state task, canonical current state outranks stronger
  archival text unless the intent explicitly requests history.
