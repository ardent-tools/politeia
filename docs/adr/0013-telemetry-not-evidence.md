# ADR: Telemetry is not automatically evidence

## Status
Accepted for starter architecture.

## Decision
Observability data becomes evidence only when a binding explicitly admits it under stronger provenance semantics.

## Consequences
- This decision is part of the greenfield architectural baseline.
- Implementations may change; semantic intent may not silently drift.
- Reversal requires an explicit superseding ADR and migration strategy.
