# Agent operating contract

Agents working in this repository must optimize for semantic correctness, not apparent task completion.

## Required behavior

- Read `START_HERE.md` before architectural work.
- Treat `docs/02-CONSTITUTION.md` as non-negotiable unless the user explicitly changes the constitution.
- Do not create a second source of authority for an existing semantic fact.
- Prefer deriving views from canonical typed representations.
- Do not make transport protocols (MCP, A2A, HTTP, CLI) own product semantics.
- Do not bypass the authorized dispatcher for protected effects.
- Do not widen delegation or policy through defaults.
- Do not make a heuristic blocking without explicit detector assurance and calibration.
- Do not allow the actor being judged to satisfy an independence requirement by self-certification.
- Do not turn inferred institutional claims into approved truth.
- Do not add production breadth before the first vertical slice is complete.
- When a new abstraction is proposed, state which ambiguity or impossible state it removes.
- If two concepts become semantically identical, collapse them.
- Prefer small trusted kernels and narrow effect interfaces.

## Completion

A change is complete only when its acceptance evidence exists and is bound to the exact artifact/version under review.

## Repository rules (fleet bindings)

- Commit messages follow conventional commits (`feat(scope):`, `fix(scope):`, ...). No AI-attribution trailers anywhere in history.
- This is a **public** repository: no client names, no client-derived material, no fleet-internal paths, and no private-system internals ever enter history. Design planning and source-mining records live in the private kanon planning area, not here.
- Project planning (ROADMAP / STATE / vision / phases) lives in the kanon planning registry, not in this repo. `docs/` here is the normative product corpus: constitution, ontology, contracts, ADRs — it ships with the code and versions with it.
