# Agent operating contract

Agents working in this repository must optimize for semantic correctness, not apparent task completion.

## Required behavior

- Read `START_HERE.md` before architectural work.
- Treat `docs/02-CONSTITUTION.md` as non-negotiable unless the user explicitly changes the constitution.
- Do not create a second source of authority for an existing semantic fact.
- Prefer deriving views from canonical typed representations.
- Do not make transport protocols (MCP, A2A, HTTP, CLI) own product semantics.
- Do not bypass the authorized dispatcher for protected effects.
- Do not treat a missing receipt or ambiguous execution outcome as proof that an effect did not run or is safe to replay.
- Do not widen delegation or policy through defaults.
- Do not make a heuristic blocking without explicit detector assurance and calibration.
- Do not call a control enforced or clean unless evidence proves it ran against the intended subject and can reach its real mediation path.
- Do not silently omit a source object from a governed population. Derive membership from its authoritative selector/manifest, record every included/excluded decision, and fail an included member with an attributable error when required semantic data is missing.
- Do not allow the actor being judged to satisfy an independence requirement by self-certification.
- Do not turn inferred institutional claims into approved truth.
- Do not add production breadth before the first vertical slice is complete.
- Keep Politeia sufficient to commission, specialize, verify, and hand off Politeia from its public source distribution; private commissioner tooling may assist but may never be required.
- Keep institution-specific data, secrets, durable state, inference authority, and production effects in the institution's trust domain by default.
- Do not hard-code a model/vendor hierarchy. Route typed execution resources only after hard policy, data, capability, and assurance requirements are satisfied.
- Treat accepted refinement packets as migration inputs. Fold their decisions into the canonical ontology, contracts, ADRs, types, and derived projections instead of preserving a second normative source.
- Preserve delivered or attested artifact bytes. Corrections and supersessions append with provenance; they do not rewrite historical evidence.
- Do not add a check without showing it can fail. An invariant implied by a stronger one beside it, a guard over a state its subject cannot reach, a comparison between a value and a recomputation of itself, and an assertion whose fixture satisfies it either way all pass identically to a working check. Reach the failure once, deliberately, before trusting the pass.
- Do not read a tool's exit status as evidence about its subject. A checker exits non-zero for a parse error, a missing input, a bad configuration and an aborted run as readily as for the defect it was pointed at, and the caller cannot tell those apart. Require the specific finding the check exists to produce.
- When a rule holds only because of where something happens to live, say so or move it. An exhaustive match is exhaustive until its type moves to another crate; a private field is unreachable until a descendant module reaches it. A guarantee that depends on an arrangement nobody stated is a guarantee that ends without warning.
- When a new abstraction is proposed, state which ambiguity or impossible state it removes.
- If two concepts become semantically identical, collapse them.
- Prefer small trusted kernels and narrow effect interfaces.

## Completion

A change is complete only when its acceptance evidence exists and is bound to the exact artifact/version under review.

## Repository rules (fleet bindings)

- Commit messages follow conventional commits (`feat(scope):`, `fix(scope):`, ...). No AI-attribution trailers anywhere in history.
- This is a **public** repository: no client names, no client-derived material, no fleet-internal paths, and no private-system internals ever enter history. Design planning and source-mining records live in the private kanon planning area, not here.
- Project planning (ROADMAP / STATE / vision / phases) lives in the kanon planning registry, not in this repo. `docs/` here is the normative product corpus: constitution, ontology, contracts, ADRs — it ships with the code and versions with it.
