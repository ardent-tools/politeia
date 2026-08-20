# ADR: Self-sufficient commissioning

## Status
Accepted for starter architecture.

## Decision
The public Politeia distribution contains the machinery required to adapt, test, verify, specialize, and hand off a client deployment without private commissioner infrastructure.

## Consequences
- Commissioning is portable into a client-controlled environment.
- Private tools may assist but cannot be required for correctness or continuity.
- A replacement authorized maintainer must be able to continue from public source and the preserved client workspace.
- Reversal requires an explicit superseding ADR and migration strategy.
