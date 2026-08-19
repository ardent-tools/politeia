# ADR: Self-maintenance without self-authorization

## Status
Accepted for starter architecture.

## Decision
Autonomous agents may reconcile and strengthen approved commitments but cannot widen authority or weaken protected commitments.

## Consequences
- This decision is part of the greenfield architectural baseline.
- Implementations may change; semantic intent may not silently drift.
- Reversal requires an explicit superseding ADR and migration strategy.
