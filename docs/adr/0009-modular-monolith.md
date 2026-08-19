# ADR: Modular monolith first

## Status
Accepted for starter architecture.

## Decision
Keep semantic boundaries explicit while avoiding premature distributed-system failure modes.

## Consequences
- This decision is part of the greenfield architectural baseline.
- Implementations may change; semantic intent may not silently drift.
- Reversal requires an explicit superseding ADR and migration strategy.
