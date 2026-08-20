# Engineering handoff

## Team directive

Treat this repository as a specification-first greenfield system.

## Before implementation

- Agree on ontology names and semantic boundaries.
- Write the first TLA+/state-machine models for delegation and operation lifecycle.
- Define canonical serialization/digest rules.
- Define the first migration format.
- Define the first transport-neutral operation envelope.
- Define orthogonal delivery, execution-outcome, epistemic-resolution, and replay-disposition state
  machines plus stable effect-subject overlap before implementing disconnected execution.
- Define the authoritative membership selector/manifest, type-or-fail boundary, and selected-source
  versus output identity proof for every first-phase governed derivation.
- Define activation evidence and the exact `ControlResult` states from `03-ONTOLOGY.md` before
  promoting a control to enforced.
- Define correction, supersession, and current-assessment projection semantics without rewriting
  delivered or attested subjects.
- Define the exact authority of bootstrap reconnaissance.
- Establish an explicit threat model for the first vertical slice.
- Define the lifecycle-profile state machine separately from deployment topology.
- Define the client trust boundary and data-flow model.
- Define the generation manifest, canonical specialization inputs, and reproducibility contract.
- Define execution-resource requirements, routing decisions, escalation, and their binding into authorization.
- Assign every `POL-A` through `POL-L` assurance claim a mechanism, evidence owner, adversarial test, residual risk, and falsifier.
- Assign `POL-M` through `POL-Q` to their named owning phase; do not claim them from prose or pull
  them into the first commissioning proof merely because their contracts are documented.

## Do not do yet

- Build a forge.
- Build a generic workflow designer.
- Build a UI framework.
- Add dozens of SaaS adapters.
- Port large rule catalogs.
- Add client-specific analytics/software-development semantics to core.
- Make MCP the semantic API.
- Introduce microservices.
- Add multiple databases.

## Exit criteria for starter phase

Politeia is sufficient to commission Politeia: the team can demonstrate the bounded first vertical slice under adversarial tests, produce artifact-bound receipts for `POL-A` through `POL-L`, and explain every trusted component required to make the demonstration valid.

A replacement maintainer can use only the public source, preserved client-owned workspace, and newly delegated client authority to derive and release the next generation. Revoking the original commissioner does not interrupt the current operational generation, and no commissioner- or vendor-owned control plane is required for continued operation or an authorized local update.
