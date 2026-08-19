# ADR: Normalized state plus immutable journals

## Status
Accepted for starter architecture.

## Decision
Use operational state for current truth and journals for provenance/evidence rather than dogmatic event sourcing.

## Consequences
- This decision is part of the greenfield architectural baseline.
- Implementations may change; semantic intent may not silently drift.
- Reversal requires an explicit superseding ADR and migration strategy.
