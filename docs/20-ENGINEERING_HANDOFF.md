# Engineering handoff

## Team directive

Treat this repository as a specification-first greenfield system.

The reference repositories are mines for proven ideas, failure modes, tests, and implementation techniques. They are not APIs to preserve.

## Before implementation

- Agree on ontology names and semantic boundaries.
- Write the first TLA+/state-machine models for delegation and operation lifecycle.
- Define canonical serialization/digest rules.
- Define the first migration format.
- Define the first transport-neutral operation envelope.
- Define the exact authority of bootstrap reconnaissance.
- Establish an explicit threat model for the first vertical slice.

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

The team can demonstrate the first vertical slice under adversarial tests and explain every trusted component required to make the demonstration valid.
