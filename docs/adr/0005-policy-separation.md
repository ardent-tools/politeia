# ADR: Separate clauses, detectors, and bindings

## Status
Accepted for starter architecture.

## Decision
Normative meaning, evidence production, and consequence are independent typed objects.

## Consequences
- This decision is part of the greenfield architectural baseline.
- Implementations may change; semantic intent may not silently drift.
- Reversal requires an explicit superseding ADR and migration strategy.
