# ADR: Monotonic capability delegation

## Status
Accepted for starter architecture.

## Decision
Delegations must be structurally provable subsets across resources, actions, effects, data classes, budgets, audience, and expiry.

## Consequences
- This decision is part of the greenfield architectural baseline.
- Implementations may change; semantic intent may not silently drift.
- Reversal requires an explicit superseding ADR and migration strategy.
