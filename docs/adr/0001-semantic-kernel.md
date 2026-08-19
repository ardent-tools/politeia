# ADR: Semantic kernel as the product center

## Status
Accepted for starter architecture.

## Decision
Adopt a small typed semantic kernel. Domain and transport breadth remains outside it.

## Consequences
- This decision is part of the greenfield architectural baseline.
- Implementations may change; semantic intent may not silently drift.
- Reversal requires an explicit superseding ADR and migration strategy.
