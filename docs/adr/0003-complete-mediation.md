# ADR: Complete mediation for protected effects

## Status
Accepted for starter architecture.

## Decision
Every productive frontend and nested protected operation passes the same authorized dispatcher.

## Consequences
- This decision is part of the greenfield architectural baseline.
- Implementations may change; semantic intent may not silently drift.
- Reversal requires an explicit superseding ADR and migration strategy.
