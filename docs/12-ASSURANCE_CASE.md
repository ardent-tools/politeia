# Assurance case

The product should be able to make and support explicit claims such as:

- all protected effects are mediated;
- delegated authority cannot exceed parent authority;
- evidence is bound to exact subjects;
- independent-verification obligations cannot be self-satisfied;
- protected policy cannot be silently weakened by local configuration;
- runtime generations cannot be mixed-and-matched;
- autonomous maintenance cannot expand its own authority;
- generated projections are reproducible;
- stale policy/runtime identities fail closed for protected operations.

Each claim must identify:

1. threat/failure model;
2. mechanism;
3. evidence;
4. adversarial test;
5. residual risk;
6. falsifier.

## Commissioning acceptance claims

The bounded first proof owns these stable claims. Their detailed tests live in `14-TESTING_STRATEGY.md`; the cited documents are the normative owners.

| ID | Claim | Normative owner |
|---|---|---|
| `POL-A` | The public distribution can commission and hand off one client deployment without private commissioner infrastructure. | `07-BOOTSTRAP.md`, `18-FIRST_VERTICAL_SLICE.md`, `20-ENGINEERING_HANDOFF.md` |
| `POL-B` | Institution data, secrets, inference authority, evidence, and operational state remain in its trust domain by default. | `09-PERSISTENCE.md`, `16-DATA_GOVERNANCE.md`, `22-DEPLOYMENT_PROFILES.md` |
| `POL-C` | Handoff narrows active capability and revokes the commissioner without breaking the operational generation. | `11-FAILURE_SEMANTICS.md`, `18-FIRST_VERTICAL_SLICE.md`, `22-DEPLOYMENT_PROFILES.md` |
| `POL-D` | Exact source and institution inputs reproduce the same generation, or declared nondeterminism explains the difference. | `15-SUPPLY_CHAIN.md` |
| `POL-E` | Resource selection satisfies all hard constraints before optimizing an ordered soft preference and records why. | `03-ONTOLOGY.md`, `18-FIRST_VERTICAL_SLICE.md` |
| `POL-F` | A hard data-locality policy prevents assignment across the forbidden inference boundary. | `16-DATA_GOVERNANCE.md` |
| `POL-G` | A verified deterministic tool is selected for work declared fully deterministic; model availability does not displace it. | `14-TESTING_STRATEGY.md`, `18-FIRST_VERTICAL_SLICE.md` |
| `POL-H` | Calibration can affect eligibility but cannot create authority, waive policy, or satisfy its own independence obligation. | `08-SELF_MANAGEMENT.md` |
| `POL-I` | One institution's private workspace is neither an input to the public core nor another institution's generation. | `09-PERSISTENCE.md`, `15-SUPPLY_CHAIN.md`, `16-DATA_GOVERNANCE.md` |
| `POL-J` | A replacement authorized maintainer can recommission without the original commissioner's accounts or systems. | `20-ENGINEERING_HANDOFF.md`, `22-DEPLOYMENT_PROFILES.md` |
| `POL-K` | Client commissioning and operation have no required dependency on commissioner-controlled or otherwise institution-external infrastructure. | `01-ANTI_SCOPE.md`, `15-SUPPLY_CHAIN.md` |
| `POL-L` | Disconnecting a vendor-hosted control plane does not disable the current generation or authorized local update path. | `09-PERSISTENCE.md`, `15-SUPPLY_CHAIN.md`, `20-ENGINEERING_HANDOFF.md` |

## Follow-on semantic claims

These claims refine later phase acceptance. Registering them does not expand or prove the bounded
`POL-A` through `POL-L` first slice.

| ID | Claim | Normative owner |
|---|---|---|
| `POL-M` | Disconnected execution binds an immutable request to target-side evidence; an unresolved overlapping effect cannot be treated as not-executed or replayed unsafely. | `04-KERNEL_CONTRACT.md`, `05-SEMANTIC_PROTOCOL.md`, `11-FAILURE_SEMANTICS.md`, `17-OBSERVABILITY_AND_EVIDENCE.md` |
| `POL-N` | Every source object receives an attributable membership decision under the authoritative selector/manifest; every included member types or fails, and selected-source versus output identity sets prove projection completeness. | `06-POLICY_COMPILER.md` |
| `POL-O` | Only `clean` with artifact-bound activation and coverage evidence may satisfy an enforced/clean claim; every other canonical `ControlResult` state remains non-clean. | `06-POLICY_COMPILER.md`, `14-TESTING_STRATEGY.md` |
| `POL-P` | Correcting or superseding a delivered/attested artifact preserves the original bytes and records a provenance-bearing relation from which the current interpretation is reproducible. | `09-PERSISTENCE.md`, `17-OBSERVABILITY_AND_EVIDENCE.md` |
| `POL-Q` | Context authorization and data eligibility are decided before relevance ranking; stale or archival material cannot silently displace canonical current state for a current-state task. | `16-DATA_GOVERNANCE.md`, `21-CONTEXT_COMPILATION.md` |

An assurance record binds the exact identities applicable to its claim: source commit, institution
workspace, subject/artifact, policy, generation/lifecycle, resource/adapter, evidence producers,
and test-harness version. A document, a test name, a green CI run, or an actor's self-certification
is not itself proof of the claim.
