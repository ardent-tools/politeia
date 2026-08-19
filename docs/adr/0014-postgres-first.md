# ADR: PostgreSQL as the first durable authority

## Status
Accepted for starter architecture.

## Decision
Stabilize one production persistence contract before offering multiple durable backends.

## Consequences
- This decision is part of the greenfield architectural baseline.
- Implementations may change; semantic intent may not silently drift.
- Reversal requires an explicit superseding ADR and migration strategy.
