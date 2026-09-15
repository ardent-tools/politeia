# Implementation dependency order

Timeless architectural prerequisites live here, not project status or scheduling. The external planning registry owns live work state.

Phase identifiers describe semantic dependencies, not isolated release gates. The first delivery composes Phases 0–4 with the context, source-completeness, correction, and learning contracts of Phase 5 and a local service/CLI transport. A library fixture is insufficient. The complete commissioning package in `18-FIRST_VERTICAL_SLICE.md` is the first product acceptance boundary. ADR `0021-institutional-learning-and-commissioning.md` records this dependency refinement; existing claim IDs and historical evidence retain their meaning.

## Phase 0 — constitutional kernel

Finalize constitution, ontology, identity, delegation, operation/effect and ambiguity/replay model,
lifecycle state machine, policy/evidence separation, semantic-orphan behavior, control activation
evidence, correction/supersession relations, threat model, assurance claims, and
migration/versioning rules. Phase 0 owns the `POL-O` activation-proof contract and executable
real-path evidence for the first enforced control. Its no-orphan contract applies to any governed
derivation introduced before the general Phase 5 projection machinery.

## Phase 1 — client-owned commissioning substrate

Implement institution-scoped workspaces, bounded reconnaissance, authenticated owner approval, private
extension/policy inputs, end-state/acceptance/remainder commissioning milestones, and
handoff/revocation records. The commissioning UX derives each displayed milestone from an end-state
predicate, bound acceptance evidence, and explicit known remainder; it is not a new kernel type.
Resolve observation/evidence provenance and approval authority at admission. Institutional knowledge may be approved before a particular operational use. Compile authorized context and discovery early enough to exercise that knowledge and collect feedback.

## Phase 2 — specialization

Derive a content-bound immutable runtime generation from exact public source, institution workspace, approved policy, lifecycle/topology, and component inputs. Prove reproducibility and atomic activation/rollback.

## Phase 3 — execution-resource routing

Implement one registry/router proof: hard constraints, one or two ordered locality/cost preferences, explicit escalation, resource binding, and independent-verification evidence.

## Phase 4 — first vertical slice

Implement the complete package and `POL-A` through `POL-L`, plus applicable `POL-N` through `POL-Q`, acceptance contracts in `18-FIRST_VERTICAL_SLICE.md`. Use two separate synthetic reference institutions and a real local service backed by PostgreSQL. The direct path includes atomic durable admission, restart, and refusal of unsafe replay after an ambiguous effect. Broader disconnected delivery under `POL-M` follows without making file bundles or another transport part of the kernel.

## Phase 5 — projections and learning loop

Derive agent context, human standards, schemas, policy bundles, and verification obligations from approved institutional truth. Close observations → findings → lessons → proposals → authenticated approved changes → projections. This semantic owner supplies governed-population type-or-fail behavior, assessment/current views, and authorization-before-ranking context (`POL-N`, `POL-P`, and `POL-Q`) to the first commissioning package. Later expansion adds projection and domain breadth without postponing this loop or creating another approval path.

## Phase 6 — transports and selected adapters

The first package exposes one semantic service through the Rust API, administrative CLI, and authenticated local Unix transport. Add first-class MCP and HTTP transports plus only the external-system adapters required by proven
deployments. A disconnected envelope/receipt transport follows the semantic `POL-M` contract; it
does not create a packet subsystem or arbitrary job scheduler.

## Phase 7 — hardening

Sandbox executable extensions, supply-chain generations, remote policy/runtime activation, disaster recovery, and high-assurance deployment topology.

Feature breadth is subordinate to semantic closure.
